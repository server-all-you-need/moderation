package httpapi

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/Xushengqwer/post_audit/internal/auditplatform"
	"github.com/Xushengqwer/post_audit/internal/moderation"
)

type stubProvider struct {
	result auditplatform.ModerationResult
	err    error
	calls  int
}

func (p *stubProvider) Moderate(_ context.Context, input auditplatform.ModerationInput) (auditplatform.ModerationResult, error) {
	p.calls++
	if p.err != nil {
		return auditplatform.ModerationResult{}, p.err
	}
	result := p.result
	result.ClientItemID = input.ClientItemID
	if result.Decision == "" {
		result.Decision = auditplatform.DecisionPass
	}
	if result.RiskLevel == "" {
		result.RiskLevel = auditplatform.RiskLevelLow
	}
	if result.ProviderName == "" {
		result.ProviderName = "stub"
	}
	return result, nil
}

func (p *stubProvider) Name() string { return "stub" }

type stubLimiter struct {
	caller       moderation.LimitOutcome
	syncProvider moderation.LimitOutcome
	err          error
	callerCalls  int
	syncCalls    int
}

func (l *stubLimiter) AcquireCaller(context.Context, string) (moderation.LimitOutcome, error) {
	l.callerCalls++
	if l.err != nil {
		return moderation.LimitOutcome{Allowed: false, Reason: moderation.LimitRedisFailure}, l.err
	}
	if l.caller.Reason != "" || l.caller.Allowed {
		return l.caller, nil
	}
	return moderation.LimitOutcome{Allowed: true}, nil
}

func (l *stubLimiter) AcquireSyncProvider(context.Context, string) (moderation.LimitOutcome, error) {
	l.syncCalls++
	if l.err != nil {
		return moderation.LimitOutcome{Allowed: false, Reason: moderation.LimitRedisFailure}, l.err
	}
	if l.syncProvider.Reason != "" || l.syncProvider.Allowed {
		return l.syncProvider, nil
	}
	return moderation.LimitOutcome{Allowed: true}, nil
}

func newTestServer(t *testing.T) (*Server, *moderation.MemoryStore, *stubProvider, *stubLimiter) {
	t.Helper()
	now := time.Date(2026, 8, 25, 10, 0, 0, 0, time.UTC)
	store := moderation.NewMemoryStore(now)
	provider := &stubProvider{}
	limiter := &stubLimiter{}
	apiKey := "test-token"
	srv, err := NewServer(Config{
		Store:    store,
		Provider: provider,
		Limiter:  limiter,
		Clients: []ClientConfig{{
			ID:          "client-a",
			Name:        "Client A",
			TokenSHA256: sha256Hex(apiKey),
			Scopes:      []string{"moderation:check", "moderation:submit", "moderation:read"},
			Webhooks:    map[string]string{"https://hooks.example.com/moderation": "secret-1"},
		}, {
			ID:          "client-readonly",
			Name:        "Readonly",
			TokenSHA256: sha256Hex("read-token"),
			Scopes:      []string{"moderation:read"},
		}},
		AdminTokenSHA256: sha256Hex("admin-token"),
		Ready: func(context.Context) error {
			return nil
		},
	})
	if err != nil {
		t.Fatalf("new server: %v", err)
	}
	return srv, store, provider, limiter
}

func doJSON(server *Server, method, path, token string, headers map[string]string, body string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(method, path, strings.NewReader(body))
	if body != "" {
		req.Header.Set("Content-Type", "application/json")
	}
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	for key, value := range headers {
		req.Header.Set(key, value)
	}
	rec := httptest.NewRecorder()
	server.Handler().ServeHTTP(rec, req)
	return rec
}

func TestPublicAuthScopesStrictJSONAndSyncProviderBudget(t *testing.T) {
	server, _, provider, limiter := newTestServer(t)

	unauth := doJSON(server, http.MethodPost, "/api/v1/moderations:check", "", nil, `{}`)
	if unauth.Code != http.StatusUnauthorized {
		t.Fatalf("missing bearer status = %d, want 401 body=%s", unauth.Code, unauth.Body.String())
	}

	forbidden := doJSON(server, http.MethodPost, "/api/v1/moderations:check", "read-token", nil, `{"client_item_id":"post-1","content_type":"text","policy":"text.general","text":"hello"}`)
	if forbidden.Code != http.StatusForbidden {
		t.Fatalf("missing check scope status = %d, want 403 body=%s", forbidden.Code, forbidden.Body.String())
	}

	unknownField := doJSON(server, http.MethodPost, "/api/v1/moderations:check", "test-token", nil, `{"client_item_id":"post-1","content_type":"text","policy":"text.general","text":"hello","extra":true}`)
	if unknownField.Code != http.StatusBadRequest || !strings.Contains(unknownField.Body.String(), `"invalid_request"`) {
		t.Fatalf("unknown field response = %d %s, want 400 invalid_request", unknownField.Code, unknownField.Body.String())
	}

	limited := doJSON(server, http.MethodPost, "/api/v1/moderations:check", "test-token", nil, `{"client_item_id":"post-1","content_type":"text","policy":"text.general","text":"hello"}`)
	if limited.Code != http.StatusOK {
		t.Fatalf("sync check status = %d, want 200 body=%s", limited.Code, limited.Body.String())
	}
	if provider.calls != 1 || limiter.callerCalls != 0 || limiter.syncCalls != 1 {
		t.Fatalf("sync must call provider once and consume combined caller+provider budget, provider=%d caller=%d sync=%d", provider.calls, limiter.callerCalls, limiter.syncCalls)
	}

	limiter.syncProvider = moderation.LimitOutcome{Allowed: false, Reason: moderation.LimitDeniedProvider}
	rateLimited := doJSON(server, http.MethodPost, "/api/v1/moderations:check", "test-token", nil, `{"client_item_id":"post-2","content_type":"text","policy":"text.general","text":"hello"}`)
	if rateLimited.Code != http.StatusTooManyRequests || !strings.Contains(rateLimited.Body.String(), `"rate_limited"`) {
		t.Fatalf("provider limit response = %d %s, want 429 rate_limited", rateLimited.Code, rateLimited.Body.String())
	}
	if provider.calls != 1 {
		t.Fatalf("provider must not be called after denied budget, calls=%d", provider.calls)
	}
}

func TestAsyncIdempotencyReplayConflictOwnershipAndNoRawContent(t *testing.T) {
	server, _, _, _ := newTestServer(t)
	body := `{"client_item_id":"post-1","content_type":"text","policy":"text.general","text":"sensitive"}`
	headers := map[string]string{"Idempotency-Key": "idem-1"}

	first := doJSON(server, http.MethodPost, "/api/v1/moderation-tasks", "test-token", headers, body)
	if first.Code != http.StatusAccepted {
		t.Fatalf("first submit status = %d, want 202 body=%s", first.Code, first.Body.String())
	}
	var firstBody map[string]interface{}
	if err := json.Unmarshal(first.Body.Bytes(), &firstBody); err != nil {
		t.Fatalf("decode first body: %v", err)
	}
	taskID, _ := firstBody["task_id"].(string)
	if taskID == "" || firstBody["status"] != "queued" {
		t.Fatalf("unexpected first body: %#v", firstBody)
	}

	replay := doJSON(server, http.MethodPost, "/api/v1/moderation-tasks", "test-token", headers, spacedJSON(body))
	if replay.Code != http.StatusAccepted {
		t.Fatalf("replay status = %d, want 202 body=%s", replay.Code, replay.Body.String())
	}
	var replayBody map[string]interface{}
	_ = json.Unmarshal(replay.Body.Bytes(), &replayBody)
	if replayBody["task_id"] != taskID {
		t.Fatalf("replay task_id = %v, want %s", replayBody["task_id"], taskID)
	}

	conflict := doJSON(server, http.MethodPost, "/api/v1/moderation-tasks", "test-token", headers, `{"client_item_id":"post-1","content_type":"text","policy":"text.general","text":"changed"}`)
	if conflict.Code != http.StatusConflict || !strings.Contains(conflict.Body.String(), `"idempotency_conflict"`) {
		t.Fatalf("conflict response = %d %s, want 409 idempotency_conflict", conflict.Code, conflict.Body.String())
	}

	got := doJSON(server, http.MethodGet, "/api/v1/moderation-tasks/"+taskID, "test-token", nil, "")
	if got.Code != http.StatusOK {
		t.Fatalf("get task status = %d, want 200 body=%s", got.Code, got.Body.String())
	}
	if strings.Contains(got.Body.String(), "sensitive") || strings.Contains(got.Body.String(), "image_url") {
		t.Fatalf("query response leaked raw content/url: %s", got.Body.String())
	}

	other := doJSON(server, http.MethodGet, "/api/v1/moderation-tasks/"+taskID, "read-token", nil, "")
	if other.Code != http.StatusNotFound {
		t.Fatalf("other caller lookup status = %d, want indistinguishable 404 body=%s", other.Code, other.Body.String())
	}
}

func TestBatchCursorPaginationInternalStatsReadinessAndOpenAPI(t *testing.T) {
	server, _, _, _ := newTestServer(t)
	headers := map[string]string{"Idempotency-Key": "batch-1"}
	batchBody := `{"webhook_url":"https://hooks.example.com/moderation","items":[{"client_item_id":"post-1","content_type":"text","policy":"text.general","text":"one"},{"client_item_id":"img-1","content_type":"image","policy":"image.general","image_url":"https://cdn.example.com/a.png"}]}`

	submitted := doJSON(server, http.MethodPost, "/api/v1/moderation-batches", "test-token", headers, batchBody)
	if submitted.Code != http.StatusAccepted {
		t.Fatalf("batch submit status = %d, want 202 body=%s", submitted.Code, submitted.Body.String())
	}
	var body map[string]interface{}
	_ = json.Unmarshal(submitted.Body.Bytes(), &body)
	batchID, _ := body["batch_id"].(string)

	page1 := doJSON(server, http.MethodGet, "/api/v1/moderation-batches/"+batchID+"/items?limit=1", "test-token", nil, "")
	if page1.Code != http.StatusOK {
		t.Fatalf("batch items page1 = %d, want 200 body=%s", page1.Code, page1.Body.String())
	}
	var page map[string]interface{}
	_ = json.Unmarshal(page1.Body.Bytes(), &page)
	if page["next_cursor"] == "" {
		t.Fatalf("first page must return deterministic opaque cursor: %#v", page)
	}
	cursor := page["next_cursor"].(string)
	page2 := doJSON(server, http.MethodGet, "/api/v1/moderation-batches/"+batchID+"/items?limit=1&cursor="+cursor, "test-token", nil, "")
	if page2.Code != http.StatusOK || strings.Contains(page2.Body.String(), "https://cdn.example.com") {
		t.Fatalf("batch items page2 = %d body=%s, want no raw URL leak", page2.Code, page2.Body.String())
	}

	adminStats := doJSON(server, http.MethodGet, "/internal/v1/moderation/stats", "admin-token", nil, "")
	if adminStats.Code != http.StatusOK || !strings.Contains(adminStats.Body.String(), "task_status_counts") || strings.Contains(adminStats.Body.String(), "TokenSHA256") {
		t.Fatalf("admin stats response = %d %s", adminStats.Code, adminStats.Body.String())
	}

	adminTask := doJSON(server, http.MethodGet, "/internal/v1/moderation/tasks/"+firstTaskIDFromPage(t, page1.Body.Bytes()), "admin-token", nil, "")
	if adminTask.Code != http.StatusOK || strings.Contains(adminTask.Body.String(), "one") {
		t.Fatalf("admin task detail = %d %s, want detail without raw text", adminTask.Code, adminTask.Body.String())
	}
	adminBatch := doJSON(server, http.MethodGet, "/internal/v1/moderation/batches/"+batchID, "admin-token", nil, "")
	if adminBatch.Code != http.StatusOK || !strings.Contains(adminBatch.Body.String(), batchID) {
		t.Fatalf("admin batch detail = %d %s", adminBatch.Code, adminBatch.Body.String())
	}
	filteredBatches := doJSON(server, http.MethodGet, "/internal/v1/moderation/batches?content_type=image&policy=image.general&caller_id=client-a", "admin-token", nil, "")
	if filteredBatches.Code != http.StatusOK || !strings.Contains(filteredBatches.Body.String(), batchID) {
		t.Fatalf("admin filtered batches = %d %s, want batch with matching image member", filteredBatches.Code, filteredBatches.Body.String())
	}

	openapi := doJSON(server, http.MethodGet, "/openapi.json", "", nil, "")
	if openapi.Code != http.StatusOK {
		t.Fatalf("openapi status = %d, want 200", openapi.Code)
	}
	if err := AssertOpenAPIParity(server.Handler(), openapi.Body.Bytes()); err != nil {
		t.Fatalf("openapi parity: %v", err)
	}
}

func firstTaskIDFromPage(t *testing.T, data []byte) string {
	t.Helper()
	var page struct {
		Items []struct {
			TaskID string `json:"task_id"`
		} `json:"items"`
	}
	if err := json.Unmarshal(data, &page); err != nil {
		t.Fatalf("decode task page: %v", err)
	}
	if len(page.Items) == 0 || page.Items[0].TaskID == "" {
		t.Fatalf("page missing task id: %s", string(data))
	}
	return page.Items[0].TaskID
}

func TestReadyzReflectsDependencies(t *testing.T) {
	server, _, _, _ := newTestServer(t)
	server.ready = func(context.Context) error { return errors.New("postgres unavailable") }

	health := doJSON(server, http.MethodGet, "/healthz", "", nil, "")
	if health.Code != http.StatusOK {
		t.Fatalf("healthz = %d, want 200", health.Code)
	}
	ready := doJSON(server, http.MethodGet, "/readyz", "", nil, "")
	if ready.Code != http.StatusServiceUnavailable || strings.Contains(ready.Body.String(), "postgres unavailable") {
		t.Fatalf("readyz = %d %s, want sanitized 503", ready.Code, ready.Body.String())
	}
}

func spacedJSON(raw string) string {
	var value interface{}
	decoder := json.NewDecoder(strings.NewReader(raw))
	if err := decoder.Decode(&value); err != nil {
		return raw
	}
	var buf bytes.Buffer
	encoder := json.NewEncoder(&buf)
	encoder.SetIndent("", "  ")
	_ = encoder.Encode(value)
	return buf.String()
}

func sha256Hex(value string) string {
	sum := sha256.Sum256([]byte(value))
	return hex.EncodeToString(sum[:])
}
