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

	"github.com/Xushengqwer/post_audit/internal/auditplatform"
	"github.com/Xushengqwer/post_audit/internal/moderation"
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
	mux       *http.ServeMux
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
	return s.mux
}

func (s *Server) routes() {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", s.healthz)
	mux.HandleFunc("GET /readyz", s.readyz)
	mux.HandleFunc("GET /openapi.json", s.openapi)
	mux.HandleFunc("POST /api/v1/moderations:check", s.handleSyncCheck)
	mux.HandleFunc("POST /api/v1/moderation-tasks", s.handleCreateTask)
	mux.HandleFunc("GET /api/v1/moderation-tasks/{id}", s.handleGetTask)
	mux.HandleFunc("POST /api/v1/moderation-batches", s.handleCreateBatch)
	mux.HandleFunc("GET /api/v1/moderation-batches/{id}", s.handleGetBatch)
	mux.HandleFunc("GET /api/v1/moderation-batches/{id}/items", s.handleBatchItems)
	mux.HandleFunc("GET /internal/v1/moderation/stats", s.handleAdminStats)
	mux.HandleFunc("GET /internal/v1/moderation/clients", s.handleAdminClients)
	mux.HandleFunc("GET /internal/v1/moderation/tasks", s.handleAdminTasks)
	mux.HandleFunc("GET /internal/v1/moderation/tasks/{id}", s.handleAdminTask)
	mux.HandleFunc("GET /internal/v1/moderation/batches", s.handleAdminBatches)
	mux.HandleFunc("GET /internal/v1/moderation/batches/{id}", s.handleAdminBatch)
	mux.HandleFunc("GET /internal/v1/moderation/batches/{id}/items", s.handleAdminBatchItems)
	s.mux = mux
}

func (s *Server) healthz(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

func (s *Server) readyz(w http.ResponseWriter, r *http.Request) {
	if err := s.ready(r.Context()); err != nil {
		writeError(w, http.StatusServiceUnavailable, "dependency_unavailable", "service dependencies are not ready")
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "ready"})
}

func (s *Server) openapi(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(openAPIJSON)
}

func (s *Server) handleSyncCheck(w http.ResponseWriter, r *http.Request) {
	client, ok := s.requirePublic(w, r, ScopeCheck)
	if !ok {
		return
	}
	var req syncModerationRequest
	if !decodeRequest(w, r, &req) {
		return
	}
	input := req.toInput()
	if err := input.Validate(); err != nil {
		writeError(w, http.StatusBadRequest, "invalid_request", err.Error())
		return
	}
	if !s.acquireSync(w, r, client.ID) {
		return
	}
	result, err := s.provider.Moderate(r.Context(), input)
	if err != nil {
		writeProviderError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, taskResultDTO(result))
}

func (s *Server) handleCreateTask(w http.ResponseWriter, r *http.Request) {
	client, ok := s.requirePublic(w, r, ScopeSubmit)
	if !ok {
		return
	}
	if !s.acquireCaller(w, r, client.ID) {
		return
	}
	idem, ok := requireIdempotencyKey(w, r)
	if !ok {
		return
	}
	var req asyncModerationRequest
	if !decodeRequest(w, r, &req) {
		return
	}
	input := req.toInput()
	if err := input.Validate(); err != nil {
		writeError(w, http.StatusBadRequest, "invalid_request", err.Error())
		return
	}
	if req.WebhookURL != "" && !client.webhookAllowed(req.WebhookURL) {
		writeError(w, http.StatusBadRequest, "invalid_request", "webhook_url is not registered")
		return
	}
	task, _, err := s.store.CreateTask(r.Context(), moderation.CreateTaskRequest{
		CallerID:       client.ID,
		Operation:      "task",
		IdempotencyKey: idem,
		PayloadHash:    canonicalHash(req),
		Input:          input,
		WebhookURL:     req.WebhookURL,
	})
	if err != nil {
		writeStoreError(w, err)
		return
	}
	writeJSON(w, http.StatusAccepted, taskAcceptedDTO(task))
}

func (s *Server) handleGetTask(w http.ResponseWriter, r *http.Request) {
	client, ok := s.requirePublic(w, r, ScopeRead)
	if !ok {
		return
	}
	if !s.acquireCaller(w, r, client.ID) {
		return
	}
	task, found, err := s.store.GetTask(r.Context(), client.ID, r.PathValue("id"))
	if err != nil {
		writeStoreError(w, err)
		return
	}
	if !found {
		writeError(w, http.StatusNotFound, "not_found", "resource not found")
		return
	}
	writeJSON(w, http.StatusOK, taskDTO(task))
}

func (s *Server) handleCreateBatch(w http.ResponseWriter, r *http.Request) {
	client, ok := s.requirePublic(w, r, ScopeSubmit)
	if !ok {
		return
	}
	if !s.acquireCaller(w, r, client.ID) {
		return
	}
	idem, ok := requireIdempotencyKey(w, r)
	if !ok {
		return
	}
	var req batchRequest
	if !decodeRequest(w, r, &req) {
		return
	}
	if len(req.Items) < 1 || len(req.Items) > 100 {
		writeError(w, http.StatusBadRequest, "invalid_request", "items length must be 1-100")
		return
	}
	inputs := make([]auditplatform.ModerationInput, 0, len(req.Items))
	for _, item := range req.Items {
		input := item.toInput()
		if err := input.Validate(); err != nil {
			writeError(w, http.StatusBadRequest, "invalid_request", err.Error())
			return
		}
		inputs = append(inputs, input)
	}
	if req.WebhookURL != "" && !client.webhookAllowed(req.WebhookURL) {
		writeError(w, http.StatusBadRequest, "invalid_request", "webhook_url is not registered")
		return
	}
	batch, _, _, err := s.store.CreateBatch(r.Context(), moderation.CreateBatchRequest{
		CallerID:       client.ID,
		Operation:      "batch",
		IdempotencyKey: idem,
		PayloadHash:    canonicalHash(req),
		Inputs:         inputs,
		WebhookURL:     req.WebhookURL,
	})
	if err != nil {
		writeStoreError(w, err)
		return
	}
	writeJSON(w, http.StatusAccepted, batchDTO(batch))
}

func (s *Server) handleGetBatch(w http.ResponseWriter, r *http.Request) {
	client, ok := s.requirePublic(w, r, ScopeRead)
	if !ok {
		return
	}
	if !s.acquireCaller(w, r, client.ID) {
		return
	}
	batch, found, err := s.store.GetBatch(r.Context(), client.ID, r.PathValue("id"))
	if err != nil {
		writeStoreError(w, err)
		return
	}
	if !found {
		writeError(w, http.StatusNotFound, "not_found", "resource not found")
		return
	}
	writeJSON(w, http.StatusOK, batchDTO(batch))
}

func (s *Server) handleBatchItems(w http.ResponseWriter, r *http.Request) {
	client, ok := s.requirePublic(w, r, ScopeRead)
	if !ok {
		return
	}
	if !s.acquireCaller(w, r, client.ID) {
		return
	}
	limit, err := queryLimit(r)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid_request", "limit must be between 1 and 100")
		return
	}
	page, err := s.store.ListBatchItems(r.Context(), client.ID, r.PathValue("id"), moderation.BatchItemCursor{Limit: limit, Cursor: r.URL.Query().Get("cursor")})
	if err != nil {
		writeStoreError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{"items": tasksDTO(page.Items), "next_cursor": page.NextCursor})
}

func (s *Server) handleAdminStats(w http.ResponseWriter, r *http.Request) {
	if !s.requireAdmin(w, r) {
		return
	}
	stats, err := s.store.AdminStats(r.Context())
	if err != nil {
		writeStoreError(w, err)
		return
	}
	if s.lag != nil {
		lag, err := s.lag.ConsumerLag(r.Context())
		if err != nil {
			writeStoreError(w, err)
			return
		}
		stats.KafkaConsumerLag = lag
	}
	writeJSON(w, http.StatusOK, stats)
}

func (s *Server) handleAdminClients(w http.ResponseWriter, r *http.Request) {
	if !s.requireAdmin(w, r) {
		return
	}
	clients, err := s.store.ListAPIClients(r.Context())
	if err != nil {
		writeStoreError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{"items": clients})
}

func (s *Server) handleAdminTasks(w http.ResponseWriter, r *http.Request) {
	if !s.requireAdmin(w, r) {
		return
	}
	filter, err := filterFromRequest(r, false)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid_request", "limit must be between 1 and 100")
		return
	}
	page, err := s.store.ListTasks(r.Context(), filter)
	if err != nil {
		writeStoreError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{"items": internalTasksDTO(page.Items), "next_cursor": page.NextCursor})
}

func (s *Server) handleAdminTask(w http.ResponseWriter, r *http.Request) {
	if !s.requireAdmin(w, r) {
		return
	}
	task, found, err := s.store.GetAdminTask(r.Context(), r.PathValue("id"))
	if err != nil {
		writeStoreError(w, err)
		return
	}
	if !found {
		writeError(w, http.StatusNotFound, "not_found", "resource not found")
		return
	}
	writeJSON(w, http.StatusOK, internalTaskDTO(task))
}

func (s *Server) handleAdminBatches(w http.ResponseWriter, r *http.Request) {
	if !s.requireAdmin(w, r) {
		return
	}
	filter, err := filterFromRequest(r, true)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid_request", "limit must be between 1 and 100")
		return
	}
	page, err := s.store.ListBatches(r.Context(), filter)
	if err != nil {
		writeStoreError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{"items": internalBatchesDTO(page.Items), "next_cursor": page.NextCursor})
}

func (s *Server) handleAdminBatch(w http.ResponseWriter, r *http.Request) {
	if !s.requireAdmin(w, r) {
		return
	}
	batch, found, err := s.store.GetAdminBatch(r.Context(), r.PathValue("id"))
	if err != nil {
		writeStoreError(w, err)
		return
	}
	if !found {
		writeError(w, http.StatusNotFound, "not_found", "resource not found")
		return
	}
	writeJSON(w, http.StatusOK, internalBatchDTO(batch))
}

func (s *Server) handleAdminBatchItems(w http.ResponseWriter, r *http.Request) {
	if !s.requireAdmin(w, r) {
		return
	}
	limit, err := queryLimit(r)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid_request", "limit must be between 1 and 100")
		return
	}
	page, err := s.store.ListAdminBatchItems(r.Context(), r.PathValue("id"), moderation.BatchItemCursor{Limit: limit, Cursor: r.URL.Query().Get("cursor")})
	if err != nil {
		writeStoreError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{"items": internalTasksDTO(page.Items), "next_cursor": page.NextCursor})
}

func (s *Server) requirePublic(w http.ResponseWriter, r *http.Request, scope string) (ClientConfig, bool) {
	client, ok := s.authenticateClient(r)
	if !ok {
		writeError(w, http.StatusUnauthorized, "unauthorized", "missing or invalid bearer token")
		return ClientConfig{}, false
	}
	if !client.hasScope(scope) {
		writeError(w, http.StatusForbidden, "forbidden", "missing required scope")
		return ClientConfig{}, false
	}
	return client, true
}

func (s *Server) requireAdmin(w http.ResponseWriter, r *http.Request) bool {
	token, ok := bearerToken(r)
	if !ok || !constantTimeSHA256(token, s.adminHash) {
		writeError(w, http.StatusUnauthorized, "unauthorized", "missing or invalid bearer token")
		return false
	}
	return true
}

func (s *Server) authenticateClient(r *http.Request) (ClientConfig, bool) {
	token, ok := bearerToken(r)
	if !ok {
		return ClientConfig{}, false
	}
	client, matched, _ := matchClientToken(token, s.clients)
	return client, matched
}

func (s *Server) acquireCaller(w http.ResponseWriter, r *http.Request, callerID string) bool {
	outcome, err := s.limiter.AcquireCaller(r.Context(), callerID)
	return writeLimitOutcome(w, outcome, err)
}

func (s *Server) acquireSync(w http.ResponseWriter, r *http.Request, callerID string) bool {
	outcome, err := s.limiter.AcquireSyncProvider(r.Context(), callerID)
	return writeLimitOutcome(w, outcome, err)
}

func writeLimitOutcome(w http.ResponseWriter, outcome moderation.LimitOutcome, err error) bool {
	if err != nil || outcome.Reason == moderation.LimitRedisFailure {
		writeError(w, http.StatusServiceUnavailable, "dependency_unavailable", "rate limiter unavailable")
		return false
	}
	if !outcome.Allowed {
		writeError(w, http.StatusTooManyRequests, "rate_limited", string(outcome.Reason))
		return false
	}
	return true
}

func decodeRequest(w http.ResponseWriter, r *http.Request, dest interface{}) bool {
	if r.Body == nil {
		writeError(w, http.StatusBadRequest, "invalid_request", "request body is required")
		return false
	}
	decoder := json.NewDecoder(http.MaxBytesReader(w, r.Body, MaxJSONBodyBytes))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(dest); err != nil {
		writeError(w, http.StatusBadRequest, "invalid_request", "invalid JSON request")
		return false
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		writeError(w, http.StatusBadRequest, "invalid_request", "request body must contain one JSON value")
		return false
	}
	return true
}

func requireIdempotencyKey(w http.ResponseWriter, r *http.Request) (string, bool) {
	key := strings.TrimSpace(r.Header.Get("Idempotency-Key"))
	if key == "" || len(key) > 128 {
		writeError(w, http.StatusBadRequest, "invalid_request", "Idempotency-Key is required")
		return "", false
	}
	return key, true
}

func bearerToken(r *http.Request) (string, bool) {
	header := r.Header.Get("Authorization")
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

func writeJSON(w http.ResponseWriter, status int, value interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(value)
}

func writeError(w http.ResponseWriter, status int, code, message string) {
	writeJSON(w, status, map[string]interface{}{"error": map[string]string{"code": code, "message": message}})
}

func writeProviderError(w http.ResponseWriter, err error) {
	var providerErr *auditplatform.ProviderError
	if errors.As(err, &providerErr) {
		status := http.StatusBadGateway
		if providerErr.Code == auditplatform.ErrorCodeInvalidInput || providerErr.Code == auditplatform.ErrorCodeInvalidRequest {
			status = http.StatusBadRequest
		}
		writeError(w, status, "provider_failure", providerErr.Code)
		return
	}
	writeError(w, http.StatusBadGateway, "provider_failure", "provider failed")
}

func writeStoreError(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, moderation.ErrIdempotencyConflict):
		writeError(w, http.StatusConflict, "idempotency_conflict", "same idempotency key was used with a different payload")
	case errors.Is(err, moderation.ErrNotFound):
		writeError(w, http.StatusNotFound, "not_found", "resource not found")
	case errors.Is(err, moderation.ErrWebhookNotAllowed):
		writeError(w, http.StatusBadRequest, "invalid_request", "webhook_url is not registered")
	case errors.Is(err, moderation.ErrInvalidCursor), errors.Is(err, moderation.ErrInvalidLimit):
		writeError(w, http.StatusBadRequest, "invalid_request", err.Error())
	default:
		writeError(w, http.StatusInternalServerError, "dependency_unavailable", "dependency unavailable")
	}
}

func canonicalHash(value interface{}) string {
	body, _ := json.Marshal(value)
	sum := sha256.Sum256(body)
	return "sha256:" + hex.EncodeToString(sum[:])
}

func queryLimit(r *http.Request) (int, error) {
	raw := r.URL.Query().Get("limit")
	if raw == "" {
		return 0, nil
	}
	limit, err := strconv.Atoi(raw)
	if err != nil || limit < 1 || limit > 100 {
		return 0, moderation.ErrInvalidLimit
	}
	return limit, nil
}

func filterFromRequest(r *http.Request, batch bool) (moderation.ListFilter, error) {
	q := r.URL.Query()
	limit, err := queryLimit(r)
	if err != nil {
		return moderation.ListFilter{}, err
	}
	filter := moderation.ListFilter{
		CallerID:    q.Get("caller_id"),
		ContentType: auditplatform.ContentType(q.Get("content_type")),
		RiskLevel:   auditplatform.RiskLevel(q.Get("risk")),
		Policy:      auditplatform.Policy(q.Get("policy")),
		Limit:       limit,
		Cursor:      q.Get("cursor"),
	}
	if batch {
		filter.BatchStatus = moderation.BatchStatus(q.Get("status"))
	} else {
		filter.TaskStatus = moderation.TaskStatus(q.Get("status"))
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
