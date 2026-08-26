package httpapi

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/server-all-you-need/moderation/internal/auditplatform"
	"github.com/server-all-you-need/moderation/internal/moderation"
)

const (
	ScopeCheck  = "moderation:check"
	ScopeSubmit = "moderation:submit"
	ScopeRead   = "moderation:read"

	MaxJSONBodyBytes = 1048576
)

type Config struct {
	Store            Store
	Provider         auditplatform.Provider
	Limiter          Limiter
	LagReporter      LagReporter
	Clients          []ClientConfig
	AdminTokenSHA256 string
	Ready            func(context.Context) error
}

type Store interface {
	moderation.Clock
	CreateTask(context.Context, moderation.CreateTaskRequest) (moderation.Task, bool, error)
	CreateBatch(context.Context, moderation.CreateBatchRequest) (moderation.Batch, []moderation.Task, bool, error)
	GetTask(context.Context, string, string) (moderation.Task, bool, error)
	GetBatch(context.Context, string, string) (moderation.Batch, bool, error)
	ListBatchItems(context.Context, string, string, moderation.BatchItemCursor) (moderation.BatchItemsPage, error)
	ListTasks(context.Context, moderation.ListFilter) (moderation.TaskPage, error)
	ListBatches(context.Context, moderation.ListFilter) (moderation.BatchPage, error)
	GetAdminTask(context.Context, string) (moderation.Task, bool, error)
	GetAdminBatch(context.Context, string) (moderation.Batch, bool, error)
	ListAdminBatchItems(context.Context, string, moderation.BatchItemCursor) (moderation.BatchItemsPage, error)
	ListAPIClients(context.Context) ([]moderation.APIClient, error)
	AdminStats(context.Context) (moderation.AdminStatsSnapshot, error)
	UpsertAPIClient(context.Context, moderation.APIClient) error
	RegisterWebhookEndpoint(context.Context, string, string, string) error
}

type Limiter interface {
	AcquireCaller(context.Context, string) (moderation.LimitOutcome, error)
	AcquireSyncProvider(context.Context, string) (moderation.LimitOutcome, error)
}

type LagReporter interface {
	ConsumerLag(context.Context) (int64, error)
}

type ClientConfig struct {
	ID          string
	Name        string
	TokenSHA256 string
	Scopes      []string
	Webhooks    map[string]string
}

type Server struct {
	store     Store
	provider  auditplatform.Provider
	limiter   Limiter
	lag       LagReporter
	clients   []ClientConfig
	adminHash string
	ready     func(context.Context) error
	engine    *gin.Engine
	publicOps []operation
}

type operation struct {
	Method string
	Path   string
}

func NewServer(cfg Config) (*Server, error) {
	if cfg.Store == nil {
		return nil, fmt.Errorf("store is required")
	}
	if cfg.Provider == nil {
		return nil, fmt.Errorf("provider is required")
	}
	if cfg.Limiter == nil {
		return nil, fmt.Errorf("limiter is required")
	}
	if cfg.AdminTokenSHA256 == "" {
		return nil, fmt.Errorf("admin token digest is required")
	}
	if cfg.Ready == nil {
		cfg.Ready = func(context.Context) error { return nil }
	}
	server := &Server{
		store:     cfg.Store,
		provider:  cfg.Provider,
		limiter:   cfg.Limiter,
		lag:       cfg.LagReporter,
		clients:   append([]ClientConfig(nil), cfg.Clients...),
		adminHash: cfg.AdminTokenSHA256,
		ready:     cfg.Ready,
		publicOps: []operation{
			{http.MethodPost, "/api/v1/moderations:check"},
			{http.MethodPost, "/api/v1/moderation-tasks"},
			{http.MethodGet, "/api/v1/moderation-tasks/{id}"},
			{http.MethodPost, "/api/v1/moderation-batches"},
			{http.MethodGet, "/api/v1/moderation-batches/{id}"},
			{http.MethodGet, "/api/v1/moderation-batches/{id}/items"},
		},
	}
	for _, client := range server.clients {
		if client.ID == "" || client.TokenSHA256 == "" {
			return nil, fmt.Errorf("api client id and token digest are required")
		}
		if err := cfg.Store.UpsertAPIClient(context.Background(), moderation.APIClient{ID: client.ID, Name: client.Name, TokenSHA256: client.TokenSHA256, Scopes: client.Scopes}); err != nil {
			return nil, err
		}
		for destination, secretID := range client.Webhooks {
			if err := cfg.Store.RegisterWebhookEndpoint(context.Background(), client.ID, destination, secretID); err != nil {
				return nil, err
			}
		}
	}
	server.routes()
	return server, nil
}

func (s *Server) Handler() http.Handler {
	return s.engine
}

func (s *Server) routes() {
	gin.SetMode(gin.ReleaseMode)
	engine := gin.New()
	engine.RedirectTrailingSlash = false
	engine.HandleMethodNotAllowed = true
	engine.Use(gin.Recovery())
	engine.GET("/healthz", s.healthz)
	engine.GET("/readyz", s.readyz)
	engine.GET("/openapi.json", s.openapi)
	engine.POST("/api/v1/moderations:check", s.handleSyncCheck)
	engine.POST("/api/v1/moderation-tasks", s.handleCreateTask)
	engine.GET("/api/v1/moderation-tasks/:id", s.handleGetTask)
	engine.POST("/api/v1/moderation-batches", s.handleCreateBatch)
	engine.GET("/api/v1/moderation-batches/:id", s.handleGetBatch)
	engine.GET("/api/v1/moderation-batches/:id/items", s.handleBatchItems)
	engine.GET("/internal/v1/moderation/stats", s.handleAdminStats)
	engine.GET("/internal/v1/moderation/clients", s.handleAdminClients)
	engine.GET("/internal/v1/moderation/tasks", s.handleAdminTasks)
	engine.GET("/internal/v1/moderation/tasks/:id", s.handleAdminTask)
	engine.GET("/internal/v1/moderation/batches", s.handleAdminBatches)
	engine.GET("/internal/v1/moderation/batches/:id", s.handleAdminBatch)
	engine.GET("/internal/v1/moderation/batches/:id/items", s.handleAdminBatchItems)
	s.engine = engine
}

func (s *Server) healthz(ctx *gin.Context) {
	writeJSON(ctx, http.StatusOK, map[string]string{"status": "ok"})
}

func (s *Server) readyz(ctx *gin.Context) {
	if err := s.ready(ctx.Request.Context()); err != nil {
		writeError(ctx, http.StatusServiceUnavailable, "dependency_unavailable", "service dependencies are not ready")
		return
	}
	writeJSON(ctx, http.StatusOK, map[string]string{"status": "ready"})
}

func (s *Server) openapi(ctx *gin.Context) {
	ctx.Header("Content-Type", "application/json")
	ctx.Status(http.StatusOK)
	_, _ = ctx.Writer.Write(openAPIJSON)
}

func (s *Server) handleSyncCheck(ctx *gin.Context) {
	client, ok := s.requirePublic(ctx, ScopeCheck)
	if !ok {
		return
	}
	var req syncModerationRequest
	if !decodeRequest(ctx, &req) {
		return
	}
	input := req.toInput()
	if err := input.Validate(); err != nil {
		writeError(ctx, http.StatusBadRequest, "invalid_request", err.Error())
		return
	}
	if !s.acquireSync(ctx, client.ID) {
		return
	}
	result, err := s.provider.Moderate(ctx.Request.Context(), input)
	if err != nil {
		writeProviderError(ctx, err)
		return
	}
	writeJSON(ctx, http.StatusOK, taskResultDTO(result))
}

func (s *Server) handleCreateTask(ctx *gin.Context) {
	client, ok := s.requirePublic(ctx, ScopeSubmit)
	if !ok {
		return
	}
	if !s.acquireCaller(ctx, client.ID) {
		return
	}
	idem, ok := requireIdempotencyKey(ctx)
	if !ok {
		return
	}
	var req asyncModerationRequest
	if !decodeRequest(ctx, &req) {
		return
	}
	input := req.toInput()
	if err := input.Validate(); err != nil {
		writeError(ctx, http.StatusBadRequest, "invalid_request", err.Error())
		return
	}
	if req.WebhookURL != "" && !client.webhookAllowed(req.WebhookURL) {
		writeError(ctx, http.StatusBadRequest, "invalid_request", "webhook_url is not registered")
		return
	}
	task, _, err := s.store.CreateTask(ctx.Request.Context(), moderation.CreateTaskRequest{
		CallerID:       client.ID,
		Operation:      "task",
		IdempotencyKey: idem,
		PayloadHash:    canonicalHash(req),
		Input:          input,
		WebhookURL:     req.WebhookURL,
	})
	if err != nil {
		writeStoreError(ctx, err)
		return
	}
	writeJSON(ctx, http.StatusAccepted, taskAcceptedDTO(task))
}

func (s *Server) handleGetTask(ctx *gin.Context) {
	client, ok := s.requirePublic(ctx, ScopeRead)
	if !ok {
		return
	}
	if !s.acquireCaller(ctx, client.ID) {
		return
	}
	task, found, err := s.store.GetTask(ctx.Request.Context(), client.ID, ctx.Param("id"))
	if err != nil {
		writeStoreError(ctx, err)
		return
	}
	if !found {
		writeError(ctx, http.StatusNotFound, "not_found", "resource not found")
		return
	}
	writeJSON(ctx, http.StatusOK, taskDTO(task))
}

func (s *Server) handleCreateBatch(ctx *gin.Context) {
	client, ok := s.requirePublic(ctx, ScopeSubmit)
	if !ok {
		return
	}
	if !s.acquireCaller(ctx, client.ID) {
		return
	}
	idem, ok := requireIdempotencyKey(ctx)
	if !ok {
		return
	}
	var req batchRequest
	if !decodeRequest(ctx, &req) {
		return
	}
	if len(req.Items) < 1 || len(req.Items) > 100 {
		writeError(ctx, http.StatusBadRequest, "invalid_request", "items length must be 1-100")
		return
	}
	inputs := make([]auditplatform.ModerationInput, 0, len(req.Items))
	for _, item := range req.Items {
		input := item.toInput()
		if err := input.Validate(); err != nil {
			writeError(ctx, http.StatusBadRequest, "invalid_request", err.Error())
			return
		}
		inputs = append(inputs, input)
	}
	if req.WebhookURL != "" && !client.webhookAllowed(req.WebhookURL) {
		writeError(ctx, http.StatusBadRequest, "invalid_request", "webhook_url is not registered")
		return
	}
	batch, _, _, err := s.store.CreateBatch(ctx.Request.Context(), moderation.CreateBatchRequest{
		CallerID:       client.ID,
		Operation:      "batch",
		IdempotencyKey: idem,
		PayloadHash:    canonicalHash(req),
		Inputs:         inputs,
		WebhookURL:     req.WebhookURL,
	})
	if err != nil {
		writeStoreError(ctx, err)
		return
	}
	writeJSON(ctx, http.StatusAccepted, batchDTO(batch))
}

func (s *Server) handleGetBatch(ctx *gin.Context) {
	client, ok := s.requirePublic(ctx, ScopeRead)
	if !ok {
		return
	}
	if !s.acquireCaller(ctx, client.ID) {
		return
	}
	batch, found, err := s.store.GetBatch(ctx.Request.Context(), client.ID, ctx.Param("id"))
	if err != nil {
		writeStoreError(ctx, err)
		return
	}
	if !found {
		writeError(ctx, http.StatusNotFound, "not_found", "resource not found")
		return
	}
	writeJSON(ctx, http.StatusOK, batchDTO(batch))
}

func (s *Server) handleBatchItems(ctx *gin.Context) {
	client, ok := s.requirePublic(ctx, ScopeRead)
	if !ok {
		return
	}
	if !s.acquireCaller(ctx, client.ID) {
		return
	}
	limit, err := queryLimit(ctx)
	if err != nil {
		writeError(ctx, http.StatusBadRequest, "invalid_request", "limit must be between 1 and 100")
		return
	}
	page, err := s.store.ListBatchItems(ctx.Request.Context(), client.ID, ctx.Param("id"), moderation.BatchItemCursor{Limit: limit, Cursor: ctx.Query("cursor")})
	if err != nil {
		writeStoreError(ctx, err)
		return
	}
	writeJSON(ctx, http.StatusOK, map[string]interface{}{"items": tasksDTO(page.Items), "next_cursor": page.NextCursor})
}

func (s *Server) handleAdminStats(ctx *gin.Context) {
	if !s.requireAdmin(ctx) {
		return
	}
	stats, err := s.store.AdminStats(ctx.Request.Context())
	if err != nil {
		writeStoreError(ctx, err)
		return
	}
	if s.lag != nil {
		lag, err := s.lag.ConsumerLag(ctx.Request.Context())
		if err != nil {
			writeStoreError(ctx, err)
			return
		}
		stats.KafkaConsumerLag = lag
	}
	writeJSON(ctx, http.StatusOK, stats)
}

func (s *Server) handleAdminClients(ctx *gin.Context) {
	if !s.requireAdmin(ctx) {
		return
	}
	clients, err := s.store.ListAPIClients(ctx.Request.Context())
	if err != nil {
		writeStoreError(ctx, err)
		return
	}
	writeJSON(ctx, http.StatusOK, map[string]interface{}{"items": clients})
}

func (s *Server) handleAdminTasks(ctx *gin.Context) {
	if !s.requireAdmin(ctx) {
		return
	}
	filter, err := filterFromRequest(ctx, false)
	if err != nil {
		writeError(ctx, http.StatusBadRequest, "invalid_request", "limit must be between 1 and 100")
		return
	}
	page, err := s.store.ListTasks(ctx.Request.Context(), filter)
	if err != nil {
		writeStoreError(ctx, err)
		return
	}
	writeJSON(ctx, http.StatusOK, map[string]interface{}{"items": internalTasksDTO(page.Items), "next_cursor": page.NextCursor})
}

func (s *Server) handleAdminTask(ctx *gin.Context) {
	if !s.requireAdmin(ctx) {
		return
	}
	task, found, err := s.store.GetAdminTask(ctx.Request.Context(), ctx.Param("id"))
	if err != nil {
		writeStoreError(ctx, err)
		return
	}
	if !found {
		writeError(ctx, http.StatusNotFound, "not_found", "resource not found")
		return
	}
	writeJSON(ctx, http.StatusOK, internalTaskDTO(task))
}

func (s *Server) handleAdminBatches(ctx *gin.Context) {
	if !s.requireAdmin(ctx) {
		return
	}
	filter, err := filterFromRequest(ctx, true)
	if err != nil {
		writeError(ctx, http.StatusBadRequest, "invalid_request", "limit must be between 1 and 100")
		return
	}
	page, err := s.store.ListBatches(ctx.Request.Context(), filter)
	if err != nil {
		writeStoreError(ctx, err)
		return
	}
	writeJSON(ctx, http.StatusOK, map[string]interface{}{"items": internalBatchesDTO(page.Items), "next_cursor": page.NextCursor})
}

func (s *Server) handleAdminBatch(ctx *gin.Context) {
	if !s.requireAdmin(ctx) {
		return
	}
	batch, found, err := s.store.GetAdminBatch(ctx.Request.Context(), ctx.Param("id"))
	if err != nil {
		writeStoreError(ctx, err)
		return
	}
	if !found {
		writeError(ctx, http.StatusNotFound, "not_found", "resource not found")
		return
	}
	writeJSON(ctx, http.StatusOK, internalBatchDTO(batch))
}

func (s *Server) handleAdminBatchItems(ctx *gin.Context) {
	if !s.requireAdmin(ctx) {
		return
	}
	limit, err := queryLimit(ctx)
	if err != nil {
		writeError(ctx, http.StatusBadRequest, "invalid_request", "limit must be between 1 and 100")
		return
	}
	page, err := s.store.ListAdminBatchItems(ctx.Request.Context(), ctx.Param("id"), moderation.BatchItemCursor{Limit: limit, Cursor: ctx.Query("cursor")})
	if err != nil {
		writeStoreError(ctx, err)
		return
	}
	writeJSON(ctx, http.StatusOK, map[string]interface{}{"items": internalTasksDTO(page.Items), "next_cursor": page.NextCursor})
}

func (s *Server) requirePublic(ctx *gin.Context, scope string) (ClientConfig, bool) {
	client, ok := s.authenticateClient(ctx)
	if !ok {
		writeError(ctx, http.StatusUnauthorized, "unauthorized", "missing or invalid bearer token")
		return ClientConfig{}, false
	}
	if !client.hasScope(scope) {
		writeError(ctx, http.StatusForbidden, "forbidden", "missing required scope")
		return ClientConfig{}, false
	}
	return client, true
}

func (s *Server) requireAdmin(ctx *gin.Context) bool {
	token, ok := bearerToken(ctx)
	if !ok || !constantTimeSHA256(token, s.adminHash) {
		writeError(ctx, http.StatusUnauthorized, "unauthorized", "missing or invalid bearer token")
		return false
	}
	return true
}

func (s *Server) authenticateClient(ctx *gin.Context) (ClientConfig, bool) {
	token, ok := bearerToken(ctx)
	if !ok {
		return ClientConfig{}, false
	}
	client, matched, _ := matchClientToken(token, s.clients)
	return client, matched
}

func (s *Server) acquireCaller(ctx *gin.Context, callerID string) bool {
	outcome, err := s.limiter.AcquireCaller(ctx.Request.Context(), callerID)
	return writeLimitOutcome(ctx, outcome, err)
}

func (s *Server) acquireSync(ctx *gin.Context, callerID string) bool {
	outcome, err := s.limiter.AcquireSyncProvider(ctx.Request.Context(), callerID)
	return writeLimitOutcome(ctx, outcome, err)
}

func writeLimitOutcome(ctx *gin.Context, outcome moderation.LimitOutcome, err error) bool {
	if err != nil || outcome.Reason == moderation.LimitRedisFailure {
		writeError(ctx, http.StatusServiceUnavailable, "dependency_unavailable", "rate limiter unavailable")
		return false
	}
	if !outcome.Allowed {
		writeError(ctx, http.StatusTooManyRequests, "rate_limited", string(outcome.Reason))
		return false
	}
	return true
}

func decodeRequest(ctx *gin.Context, dest interface{}) bool {
	if ctx.Request.Body == nil {
		writeError(ctx, http.StatusBadRequest, "invalid_request", "request body is required")
		return false
	}
	decoder := json.NewDecoder(http.MaxBytesReader(ctx.Writer, ctx.Request.Body, MaxJSONBodyBytes))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(dest); err != nil {
		writeError(ctx, http.StatusBadRequest, "invalid_request", "invalid JSON request")
		return false
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		writeError(ctx, http.StatusBadRequest, "invalid_request", "request body must contain one JSON value")
		return false
	}
	return true
}

func requireIdempotencyKey(ctx *gin.Context) (string, bool) {
	key := strings.TrimSpace(ctx.GetHeader("Idempotency-Key"))
	if key == "" || len(key) > 128 {
		writeError(ctx, http.StatusBadRequest, "invalid_request", "Idempotency-Key is required")
		return "", false
	}
	return key, true
}

func bearerToken(ctx *gin.Context) (string, bool) {
	header := ctx.GetHeader("Authorization")
	const prefix = "Bearer "
	if !strings.HasPrefix(header, prefix) {
		return "", false
	}
	token := strings.TrimSpace(strings.TrimPrefix(header, prefix))
	return token, token != ""
}

func constantTimeSHA256(token, expectedHex string) bool {
	sum := sha256.Sum256([]byte(token))
	actual := hex.EncodeToString(sum[:])
	return subtle.ConstantTimeCompare([]byte(actual), []byte(expectedHex)) == 1
}

func matchClientToken(token string, clients []ClientConfig) (ClientConfig, bool, int) {
	var matched ClientConfig
	found := false
	comparisons := 0
	for _, client := range clients {
		comparisons++
		if constantTimeSHA256(token, client.TokenSHA256) {
			matched = client
			found = true
		}
	}
	return matched, found, comparisons
}

func (c ClientConfig) hasScope(scope string) bool {
	for _, candidate := range c.Scopes {
		if candidate == scope {
			return true
		}
	}
	return false
}

func (c ClientConfig) webhookAllowed(url string) bool {
	if url == "" {
		return true
	}
	_, ok := c.Webhooks[url]
	return ok
}

type syncModerationRequest struct {
	ClientItemID string                    `json:"client_item_id"`
	ContentType  auditplatform.ContentType `json:"content_type"`
	Policy       auditplatform.Policy      `json:"policy"`
	Text         string                    `json:"text,omitempty"`
	ImageURL     string                    `json:"image_url,omitempty"`
}

func (r syncModerationRequest) toInput() auditplatform.ModerationInput {
	return auditplatform.ModerationInput{
		ClientItemID: r.ClientItemID,
		ContentType:  r.ContentType,
		Policy:       r.Policy,
		Text:         r.Text,
		ImageURL:     r.ImageURL,
	}
}

type asyncModerationRequest struct {
	ClientItemID string                    `json:"client_item_id"`
	ContentType  auditplatform.ContentType `json:"content_type"`
	Policy       auditplatform.Policy      `json:"policy"`
	Text         string                    `json:"text,omitempty"`
	ImageURL     string                    `json:"image_url,omitempty"`
	WebhookURL   string                    `json:"webhook_url,omitempty"`
}

func (r asyncModerationRequest) toInput() auditplatform.ModerationInput {
	return auditplatform.ModerationInput{
		ClientItemID: r.ClientItemID,
		ContentType:  r.ContentType,
		Policy:       r.Policy,
		Text:         r.Text,
		ImageURL:     r.ImageURL,
	}
}

type batchRequest struct {
	Items      []syncModerationRequest `json:"items"`
	WebhookURL string                  `json:"webhook_url,omitempty"`
}

type taskResponse struct {
	TaskID            string                     `json:"task_id"`
	BatchID           string                     `json:"batch_id,omitempty"`
	ClientItemID      string                     `json:"client_item_id"`
	ContentType       auditplatform.ContentType  `json:"content_type"`
	Policy            auditplatform.Policy       `json:"policy"`
	Status            moderation.TaskStatus      `json:"status"`
	Decision          auditplatform.Decision     `json:"decision,omitempty"`
	RiskLevel         auditplatform.RiskLevel    `json:"risk_level,omitempty"`
	Labels            []auditplatform.LabelEntry `json:"labels,omitempty"`
	ProviderName      string                     `json:"provider_name,omitempty"`
	ProviderRequestID string                     `json:"provider_request_id,omitempty"`
	ProviderDataID    string                     `json:"provider_data_id,omitempty"`
	Error             *moderation.TaskError      `json:"error,omitempty"`
	Attempts          int                        `json:"attempts"`
	CreatedAt         time.Time                  `json:"created_at"`
	UpdatedAt         time.Time                  `json:"updated_at"`
	TerminalAt        *time.Time                 `json:"terminal_at,omitempty"`
}

type internalTaskResponse struct {
	CallerID string `json:"caller_id"`
	taskResponse
}

func taskAcceptedDTO(task moderation.Task) map[string]interface{} {
	return map[string]interface{}{
		"task_id": task.ID,
		"status":  task.Status,
	}
}

func taskDTO(task moderation.Task) taskResponse {
	out := taskResponse{
		TaskID:       task.ID,
		BatchID:      task.BatchID,
		ClientItemID: task.ClientItemID,
		ContentType:  task.ContentType,
		Policy:       task.Policy,
		Status:       task.Status,
		Error:        task.Error,
		Attempts:     task.Attempts,
		CreatedAt:    task.CreatedAt,
		UpdatedAt:    task.UpdatedAt,
		TerminalAt:   task.TerminalAt,
	}
	if task.Result != nil {
		out.Decision = task.Result.Decision
		out.RiskLevel = task.Result.RiskLevel
		out.Labels = task.Result.Labels
		out.ProviderName = task.Result.ProviderName
		out.ProviderRequestID = task.Result.ProviderRequestID
		out.ProviderDataID = task.Result.ProviderDataID
	}
	return out
}

func internalTaskDTO(task moderation.Task) internalTaskResponse {
	return internalTaskResponse{CallerID: task.CallerID, taskResponse: taskDTO(task)}
}

func taskResultDTO(result auditplatform.ModerationResult) map[string]interface{} {
	return map[string]interface{}{
		"client_item_id":      result.ClientItemID,
		"decision":            result.Decision,
		"risk_level":          result.RiskLevel,
		"labels":              result.Labels,
		"provider_name":       result.ProviderName,
		"provider_request_id": result.ProviderRequestID,
		"provider_data_id":    result.ProviderDataID,
	}
}

func tasksDTO(tasks []moderation.Task) []taskResponse {
	out := make([]taskResponse, 0, len(tasks))
	for _, task := range tasks {
		out = append(out, taskDTO(task))
	}
	return out
}

func internalTasksDTO(tasks []moderation.Task) []internalTaskResponse {
	out := make([]internalTaskResponse, 0, len(tasks))
	for _, task := range tasks {
		out = append(out, internalTaskDTO(task))
	}
	return out
}

type batchResponse struct {
	BatchID    string                 `json:"batch_id"`
	Status     moderation.BatchStatus `json:"status"`
	Total      int                    `json:"total"`
	Queued     int                    `json:"queued"`
	Processing int                    `json:"processing"`
	Succeeded  int                    `json:"succeeded"`
	Failed     int                    `json:"failed"`
	CreatedAt  time.Time              `json:"created_at"`
	UpdatedAt  time.Time              `json:"updated_at"`
	TerminalAt *time.Time             `json:"terminal_at,omitempty"`
}

type internalBatchResponse struct {
	CallerID string `json:"caller_id"`
	batchResponse
}

func batchDTO(batch moderation.Batch) batchResponse {
	return batchResponse{
		BatchID:    batch.ID,
		Status:     batch.Status,
		Total:      batch.Total,
		Queued:     batch.Queued,
		Processing: batch.Processing,
		Succeeded:  batch.Succeeded,
		Failed:     batch.Failed,
		CreatedAt:  batch.CreatedAt,
		UpdatedAt:  batch.UpdatedAt,
		TerminalAt: batch.TerminalAt,
	}
}

func internalBatchDTO(batch moderation.Batch) internalBatchResponse {
	return internalBatchResponse{CallerID: batch.CallerID, batchResponse: batchDTO(batch)}
}

func batchesDTO(batches []moderation.Batch) []batchResponse {
	out := make([]batchResponse, 0, len(batches))
	for _, batch := range batches {
		out = append(out, batchDTO(batch))
	}
	return out
}

func internalBatchesDTO(batches []moderation.Batch) []internalBatchResponse {
	out := make([]internalBatchResponse, 0, len(batches))
	for _, batch := range batches {
		out = append(out, internalBatchDTO(batch))
	}
	return out
}

func writeJSON(ctx *gin.Context, status int, value interface{}) {
	ctx.Header("Content-Type", "application/json")
	ctx.Status(status)
	_ = json.NewEncoder(ctx.Writer).Encode(value)
}

func writeError(ctx *gin.Context, status int, code, message string) {
	writeJSON(ctx, status, map[string]interface{}{"error": map[string]string{"code": code, "message": message}})
}

func writeProviderError(ctx *gin.Context, err error) {
	var providerErr *auditplatform.ProviderError
	if errors.As(err, &providerErr) {
		status := http.StatusBadGateway
		if providerErr.Code == auditplatform.ErrorCodeInvalidInput || providerErr.Code == auditplatform.ErrorCodeInvalidRequest {
			status = http.StatusBadRequest
		}
		writeError(ctx, status, "provider_failure", providerErr.Code)
		return
	}
	writeError(ctx, http.StatusBadGateway, "provider_failure", "provider failed")
}

func writeStoreError(ctx *gin.Context, err error) {
	switch {
	case errors.Is(err, moderation.ErrIdempotencyConflict):
		writeError(ctx, http.StatusConflict, "idempotency_conflict", "same idempotency key was used with a different payload")
	case errors.Is(err, moderation.ErrNotFound):
		writeError(ctx, http.StatusNotFound, "not_found", "resource not found")
	case errors.Is(err, moderation.ErrWebhookNotAllowed):
		writeError(ctx, http.StatusBadRequest, "invalid_request", "webhook_url is not registered")
	case errors.Is(err, moderation.ErrInvalidCursor), errors.Is(err, moderation.ErrInvalidLimit):
		writeError(ctx, http.StatusBadRequest, "invalid_request", err.Error())
	default:
		writeError(ctx, http.StatusInternalServerError, "dependency_unavailable", "dependency unavailable")
	}
}

func canonicalHash(value interface{}) string {
	body, _ := json.Marshal(value)
	sum := sha256.Sum256(body)
	return "sha256:" + hex.EncodeToString(sum[:])
}

func queryLimit(ctx *gin.Context) (int, error) {
	raw := ctx.Query("limit")
	if raw == "" {
		return 0, nil
	}
	limit, err := strconv.Atoi(raw)
	if err != nil || limit < 1 || limit > 100 {
		return 0, moderation.ErrInvalidLimit
	}
	return limit, nil
}

func filterFromRequest(ctx *gin.Context, batch bool) (moderation.ListFilter, error) {
	limit, err := queryLimit(ctx)
	if err != nil {
		return moderation.ListFilter{}, err
	}
	filter := moderation.ListFilter{
		CallerID:    ctx.Query("caller_id"),
		ContentType: auditplatform.ContentType(ctx.Query("content_type")),
		RiskLevel:   auditplatform.RiskLevel(ctx.Query("risk")),
		Policy:      auditplatform.Policy(ctx.Query("policy")),
		Limit:       limit,
		Cursor:      ctx.Query("cursor"),
	}
	if batch {
		filter.BatchStatus = moderation.BatchStatus(ctx.Query("status"))
	} else {
		filter.TaskStatus = moderation.TaskStatus(ctx.Query("status"))
	}
	return filter, nil
}

func AssertOpenAPIParity(handler http.Handler, document []byte) error {
	var spec struct {
		Paths map[string]map[string]struct {
			Responses map[string]interface{} `json:"responses"`
		} `json:"paths"`
	}
	if err := json.Unmarshal(document, &spec); err != nil {
		return err
	}
	expected := []operation{
		{http.MethodPost, "/api/v1/moderations:check"},
		{http.MethodPost, "/api/v1/moderation-tasks"},
		{http.MethodGet, "/api/v1/moderation-tasks/{id}"},
		{http.MethodPost, "/api/v1/moderation-batches"},
		{http.MethodGet, "/api/v1/moderation-batches/{id}"},
		{http.MethodGet, "/api/v1/moderation-batches/{id}/items"},
	}
	for _, op := range expected {
		methods, ok := spec.Paths[op.Path]
		if !ok {
			return fmt.Errorf("openapi missing path %s", op.Path)
		}
		operation, ok := methods[strings.ToLower(op.Method)]
		if !ok {
			return fmt.Errorf("openapi missing operation %s %s", op.Method, op.Path)
		}
		for _, status := range expectedOpenAPIStatuses(op.Method, op.Path) {
			if _, ok := operation.Responses[status]; !ok {
				return fmt.Errorf("openapi missing response %s for %s %s", status, op.Method, op.Path)
			}
		}
	}
	for path, methods := range spec.Paths {
		if !strings.HasPrefix(path, "/api/v1/") {
			continue
		}
		for method := range methods {
			if !operationListed(expected, strings.ToUpper(method), path) {
				return fmt.Errorf("openapi documents unimplemented public operation %s %s", strings.ToUpper(method), path)
			}
		}
	}
	for _, op := range expected {
		req := httptestRequest(op.Method, pathForMux(op.Path))
		rec := httptestRecorder()
		handler.ServeHTTP(rec, req)
		if rec.Code == http.StatusNotFound {
			return fmt.Errorf("handler missing public operation %s %s", op.Method, op.Path)
		}
	}
	if !bytes.Contains(document, []byte(`"Idempotency-Key"`)) || !bytes.Contains(document, []byte(`"Authorization"`)) {
		return fmt.Errorf("openapi must declare auth and idempotency headers")
	}
	return nil
}

func expectedOpenAPIStatuses(method, path string) []string {
	switch method + " " + path {
	case http.MethodPost + " /api/v1/moderations:check":
		return []string{"200", "400", "401", "403", "429", "502", "503"}
	case http.MethodPost + " /api/v1/moderation-tasks", http.MethodPost + " /api/v1/moderation-batches":
		return []string{"202", "400", "401", "403", "409", "429", "503"}
	case http.MethodGet + " /api/v1/moderation-tasks/{id}", http.MethodGet + " /api/v1/moderation-batches/{id}", http.MethodGet + " /api/v1/moderation-batches/{id}/items":
		return []string{"200", "400", "401", "403", "404", "429", "503"}
	default:
		return nil
	}
}

func operationListed(ops []operation, method, path string) bool {
	for _, op := range ops {
		if op.Method == method && op.Path == path {
			return true
		}
	}
	return false
}

func pathForMux(path string) string {
	path = strings.ReplaceAll(path, "{id}", "resource-id")
	return path
}

func httptestRequest(method, path string) *http.Request {
	req, _ := http.NewRequest(method, path, nil)
	return req
}

type responseRecorder struct {
	header http.Header
	Code   int
}

func httptestRecorder() *responseRecorder {
	return &responseRecorder{header: http.Header{}, Code: 200}
}

func (r *responseRecorder) Header() http.Header       { return r.header }
func (r *responseRecorder) WriteHeader(status int)    { r.Code = status }
func (r *responseRecorder) Write([]byte) (int, error) { return 0, nil }
