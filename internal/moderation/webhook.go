package moderation

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/http"
	"net/url"
	"sort"
	"time"
)

func WebhookAttemptSchedule() []time.Duration {
	return []time.Duration{0, time.Minute, 5 * time.Minute, 30 * time.Minute, 2 * time.Hour, 12 * time.Hour}
}

func SignWebhook(secret string, timestamp time.Time, rawBody []byte) string {
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(timestamp.Format(time.RFC3339)))
	mac.Write([]byte("."))
	mac.Write(rawBody)
	return "sha256=" + hex.EncodeToString(mac.Sum(nil))
}

type WebhookHTTPClient interface {
	DoWebhook(ctx context.Context, url string, headers http.Header, body []byte) (int, error)
}

type WebhookDispatcher struct {
	store *MemoryStore
	http  WebhookHTTPClient
}

func NewWebhookDispatcher(store *MemoryStore, httpClient WebhookHTTPClient) *WebhookDispatcher {
	return &WebhookDispatcher{store: store, http: httpClient}
}

func (d *WebhookDispatcher) DispatchDueWebhooks(ctx context.Context, limit int) error {
	rows := d.store.DueWebhookOutbox(limit)
	for _, row := range rows {
		timestamp := d.store.Now()
		secret, ok := d.store.webhookSecret(row.CallerID, row.DestinationURL)
		if !ok {
			d.store.RecordWebhookAttempt(row.ID, 0, ErrWebhookNotAllowed)
			continue
		}
		headers := http.Header{}
		headers.Set("Content-Type", "application/json")
		headers.Set("X-Moderation-Timestamp", timestamp.Format(time.RFC3339))
		headers.Set("X-Moderation-Signature", SignWebhook(secret, timestamp, row.RawBody))

		statusCode, err := d.http.DoWebhook(ctx, row.DestinationURL, headers, row.RawBody)
		if err == nil && (statusCode < 200 || statusCode >= 300) {
			err = fmt.Errorf("webhook returned status %d", statusCode)
		}
		d.store.RecordWebhookAttempt(row.ID, statusCode, err)
	}
	return nil
}

func validateWebhookURL(raw string) error {
	parsed, err := url.Parse(raw)
	if err != nil {
		return err
	}
	if parsed.Scheme != "https" || parsed.Host == "" || parsed.User != nil {
		return ErrWebhookNotAllowed
	}
	return nil
}

func sortWebhookRows(rows []WebhookOutboxRow) {
	sort.Slice(rows, func(i, j int) bool {
		if rows[i].NextAttemptAt.Equal(rows[j].NextAttemptAt) {
			return rows[i].ID < rows[j].ID
		}
		return rows[i].NextAttemptAt.Before(rows[j].NextAttemptAt)
	})
}
