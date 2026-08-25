package moderation

import (
	"bytes"
	"context"
	"io"
	"net/http"
)

type NetWebhookClient struct {
	Client *http.Client
}

func (c NetWebhookClient) DoWebhook(ctx context.Context, url string, headers http.Header, body []byte) (int, error) {
	client := c.Client
	if client == nil {
		client = http.DefaultClient
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return 0, err
	}
	req.Header = headers.Clone()
	resp, err := client.Do(req)
	if err != nil {
		return 0, err
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 4096))
	return resp.StatusCode, nil
}
