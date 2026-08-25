package aliyunclient

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/Xushengqwer/go-common/core"
	"github.com/Xushengqwer/post_audit/internal/auditplatform"
	"github.com/Xushengqwer/post_audit/internal/config"
	openapi "github.com/alibabacloud-go/darabonba-openapi/v2/client"
	green "github.com/alibabacloud-go/green-20220302/v3/client"
	"github.com/alibabacloud-go/tea/dara"
	"github.com/alibabacloud-go/tea/tea"
	"go.uber.org/zap"
)

type greenModerationSDK interface {
	TextModerationPlusWithContext(context.Context, *green.TextModerationPlusRequest, *dara.RuntimeOptions) (*green.TextModerationPlusResponse, error)
	ImageModerationWithContext(context.Context, *green.ImageModerationRequest, *dara.RuntimeOptions) (*green.ImageModerationResponse, error)
}

type AliyunClientConfig struct {
	AccessKeyID     string
	AccessKeySecret string
	Region          string
	Endpoint        string
	ConnectTimeout  time.Duration
	ReadTimeout     time.Duration
}

type AliyunAuditClient struct {
	client         greenModerationSDK
	logger         *core.ZapLogger
	connectTimeout time.Duration
	readTimeout    time.Duration
}

func NewAliyunAuditClient(cfg config.AliyunConfig, logger *core.ZapLogger) (*AliyunAuditClient, error) {
	timeout := time.Duration(cfg.TimeoutMs) * time.Millisecond
	return NewAliyunModerationClient(AliyunClientConfig{
		AccessKeyID:     cfg.AccessKeyID,
		AccessKeySecret: cfg.AccessKeySecret,
		Region:          cfg.RegionID,
		Endpoint:        cfg.Endpoint,
		ConnectTimeout:  timeout,
		ReadTimeout:     timeout,
	}, logger)
}

func NewAliyunModerationClient(cfg AliyunClientConfig, logger *core.ZapLogger) (*AliyunAuditClient, error) {
	if cfg.AccessKeyID == "" || cfg.AccessKeySecret == "" {
		return nil, &auditplatform.ProviderError{Code: auditplatform.ErrorCodeAuthentication, Message: "aliyun access key id and secret are required"}
	}
	if cfg.Region == "" {
		return nil, &auditplatform.ProviderError{Code: auditplatform.ErrorCodeInvalidRequest, Message: "aliyun region is required"}
	}
	if cfg.Endpoint == "" {
		return nil, &auditplatform.ProviderError{Code: auditplatform.ErrorCodeInvalidRequest, Message: "aliyun endpoint is required"}
	}

	openapiConfig := &openapi.Config{
		AccessKeyId:     tea.String(cfg.AccessKeyID),
		AccessKeySecret: tea.String(cfg.AccessKeySecret),
		RegionId:        tea.String(cfg.Region),
		Endpoint:        tea.String(cfg.Endpoint),
	}
	client, err := green.NewClient(openapiConfig)
	if err != nil {
		return nil, &auditplatform.ProviderError{Code: auditplatform.ErrorCodeInvalidRequest, Message: "create aliyun green client failed", Err: err}
	}
	if logger != nil {
		logger.Info("阿里云 green 内容安全客户端初始化成功", zap.String("endpoint", cfg.Endpoint), zap.String("region", cfg.Region))
	}
	return &AliyunAuditClient{
		client:         client,
		logger:         logger,
		connectTimeout: cfg.ConnectTimeout,
		readTimeout:    cfg.ReadTimeout,
	}, nil
}

func newAliyunAuditClientWithSDK(client greenModerationSDK, connectTimeout, readTimeout time.Duration) *AliyunAuditClient {
	return &AliyunAuditClient{
		client:         client,
		connectTimeout: connectTimeout,
		readTimeout:    readTimeout,
	}
}

func (c *AliyunAuditClient) Name() string {
	return "aliyun"
}

func (c *AliyunAuditClient) Moderate(ctx context.Context, input auditplatform.ModerationInput) (auditplatform.ModerationResult, error) {
	if err := input.Validate(); err != nil {
		return auditplatform.ModerationResult{}, &auditplatform.ProviderError{Code: auditplatform.ErrorCodeInvalidInput, Message: err.Error(), Err: err}
	}
	spec, _ := auditplatform.LookupPolicy(input.Policy)
	if c.client == nil {
		return auditplatform.ModerationResult{}, &auditplatform.ProviderError{Code: auditplatform.ErrorCodeInvalidRequest, Message: "aliyun green client is nil"}
	}

	switch input.ContentType {
	case auditplatform.ContentTypeText:
		return c.moderateText(ctx, input, spec.ProviderService)
	case auditplatform.ContentTypeImage:
		return c.moderateImage(ctx, input, spec.ProviderService)
	default:
		return auditplatform.ModerationResult{}, &auditplatform.ProviderError{Code: auditplatform.ErrorCodeInvalidInput, Message: "unsupported content type"}
	}
}

func (c *AliyunAuditClient) moderateText(ctx context.Context, input auditplatform.ModerationInput, service string) (auditplatform.ModerationResult, error) {
	serviceParams, err := json.Marshal(map[string]string{
		"content": input.Text,
		"dataId":  input.ClientItemID,
	})
	if err != nil {
		return auditplatform.ModerationResult{}, &auditplatform.ProviderError{Code: auditplatform.ErrorCodeInvalidRequest, Message: "marshal text moderation parameters failed", Err: err}
	}

	response, err := c.client.TextModerationPlusWithContext(ctx, &green.TextModerationPlusRequest{
		Service:           tea.String(service),
		ServiceParameters: tea.String(string(serviceParams)),
	}, c.runtimeOptions())
	if err != nil {
		return auditplatform.ModerationResult{}, classifyProviderError(err)
	}
	if response == nil || response.Body == nil {
		return auditplatform.ModerationResult{}, &auditplatform.ProviderError{Code: auditplatform.ErrorCodeProviderResponse, Message: "aliyun text moderation response body is missing"}
	}
	if err := providerStatusError(tea.Int32Value(response.StatusCode), tea.Int32Value(response.Body.Code)); err != nil {
		return auditplatform.ModerationResult{}, err
	}
	if response.Body.Data == nil {
		return auditplatform.ModerationResult{}, &auditplatform.ProviderError{Code: auditplatform.ErrorCodeProviderResponse, Message: "aliyun text moderation response data is missing"}
	}

	data := response.Body.Data
	risk, decision, err := auditplatform.NormalizeRiskLevel(tea.StringValue(data.RiskLevel))
	if err != nil {
		return auditplatform.ModerationResult{}, err
	}
	return auditplatform.ModerationResult{
		ClientItemID:      input.ClientItemID,
		Decision:          decision,
		RiskLevel:         risk,
		ProviderName:      c.Name(),
		ProviderRequestID: tea.StringValue(response.Body.RequestId),
		ProviderDataID:    tea.StringValue(data.DataId),
		Labels:            normalizeTextLabels(data.Result),
	}, nil
}

func (c *AliyunAuditClient) moderateImage(ctx context.Context, input auditplatform.ModerationInput, service string) (auditplatform.ModerationResult, error) {
	serviceParams, err := json.Marshal(map[string]string{
		"imageUrl": input.ImageURL,
		"dataId":   input.ClientItemID,
	})
	if err != nil {
		return auditplatform.ModerationResult{}, &auditplatform.ProviderError{Code: auditplatform.ErrorCodeInvalidRequest, Message: "marshal image moderation parameters failed", Err: err}
	}

	response, err := c.client.ImageModerationWithContext(ctx, &green.ImageModerationRequest{
		Service:           tea.String(service),
		ServiceParameters: tea.String(string(serviceParams)),
	}, c.runtimeOptions())
	if err != nil {
		return auditplatform.ModerationResult{}, classifyProviderError(err)
	}
	if response == nil || response.Body == nil {
		return auditplatform.ModerationResult{}, &auditplatform.ProviderError{Code: auditplatform.ErrorCodeProviderResponse, Message: "aliyun image moderation response body is missing"}
	}
	if err := providerStatusError(tea.Int32Value(response.StatusCode), tea.Int32Value(response.Body.Code)); err != nil {
		return auditplatform.ModerationResult{}, err
	}
	if response.Body.Data == nil {
		return auditplatform.ModerationResult{}, &auditplatform.ProviderError{Code: auditplatform.ErrorCodeProviderResponse, Message: "aliyun image moderation response data is missing"}
	}

	data := response.Body.Data
	risk, decision, err := auditplatform.NormalizeRiskLevel(tea.StringValue(data.RiskLevel))
	if err != nil {
		return auditplatform.ModerationResult{}, err
	}
	return auditplatform.ModerationResult{
		ClientItemID:      input.ClientItemID,
		Decision:          decision,
		RiskLevel:         risk,
		ProviderName:      c.Name(),
		ProviderRequestID: tea.StringValue(response.Body.RequestId),
		ProviderDataID:    tea.StringValue(data.DataId),
		Labels:            normalizeImageLabels(data.Result),
	}, nil
}

func (c *AliyunAuditClient) runtimeOptions() *dara.RuntimeOptions {
	options := &dara.RuntimeOptions{}
	if c.connectTimeout > 0 {
		options.ConnectTimeout = tea.Int(int(c.connectTimeout.Milliseconds()))
	}
	if c.readTimeout > 0 {
		options.ReadTimeout = tea.Int(int(c.readTimeout.Milliseconds()))
	}
	return options
}

func normalizeTextLabels(results []*green.TextModerationPlusResponseBodyDataResult) []auditplatform.LabelEntry {
	labels := make([]auditplatform.LabelEntry, 0, len(results))
	for _, result := range results {
		if result == nil {
			continue
		}
		labels = append(labels, auditplatform.LabelEntry{
			Label:       tea.StringValue(result.Label),
			Confidence:  float64(tea.Float32Value(result.Confidence)),
			Description: tea.StringValue(result.Description),
			RiskWords:   splitRiskWords(tea.StringValue(result.RiskWords)),
		})
	}
	return labels
}

func normalizeImageLabels(results []*green.ImageModerationResponseBodyDataResult) []auditplatform.LabelEntry {
	labels := make([]auditplatform.LabelEntry, 0, len(results))
	for _, result := range results {
		if result == nil {
			continue
		}
		labels = append(labels, auditplatform.LabelEntry{
			Label:       tea.StringValue(result.Label),
			Confidence:  float64(tea.Float32Value(result.Confidence)),
			Description: tea.StringValue(result.Description),
		})
	}
	return labels
}

func splitRiskWords(raw string) []string {
	fields := strings.FieldsFunc(raw, func(r rune) bool {
		return r == ',' || r == '，'
	})
	words := make([]string, 0, len(fields))
	for _, field := range fields {
		word := strings.TrimSpace(field)
		if word != "" {
			words = append(words, word)
		}
	}
	return words
}

func providerStatusError(httpStatus, bodyCode int32) error {
	if httpStatus == 200 && bodyCode == 200 {
		return nil
	}
	if bodyCode != 0 && bodyCode != 200 {
		return providerBodyCodeError(bodyCode)
	}
	return providerHTTPStatusError(httpStatus)
}

func providerBodyCodeError(code int32) error {
	switch code {
	case 403, 429, 588:
		return &auditplatform.ProviderError{Code: auditplatform.ErrorCodeThrottled, Retryable: true, Message: "aliyun throttled"}
	case 408:
		return &auditplatform.ProviderError{Code: auditplatform.ErrorCodePermission, Message: "aliyun permission error"}
	case 581:
		return &auditplatform.ProviderError{Code: auditplatform.ErrorCodeTimeout, Retryable: true, Message: "aliyun request timeout"}
	}
	if code >= 500 {
		return &auditplatform.ProviderError{Code: auditplatform.ErrorCodeProviderTemporary, Retryable: true, Message: fmt.Sprintf("aliyun provider temporary error: %d", code)}
	}
	return &auditplatform.ProviderError{Code: auditplatform.ErrorCodeInvalidRequest, Message: fmt.Sprintf("aliyun invalid request: %d", code)}
}

func providerHTTPStatusError(status int32) error {
	switch status {
	case 200:
		return &auditplatform.ProviderError{Code: auditplatform.ErrorCodeInvalidRequest, Message: "aliyun invalid request"}
	case 401:
		return &auditplatform.ProviderError{Code: auditplatform.ErrorCodeAuthentication, Message: "aliyun authentication error"}
	case 403:
		return &auditplatform.ProviderError{Code: auditplatform.ErrorCodePermission, Message: "aliyun permission error"}
	case 408:
		return &auditplatform.ProviderError{Code: auditplatform.ErrorCodeTimeout, Retryable: true, Message: "aliyun request timeout"}
	case 429:
		return &auditplatform.ProviderError{Code: auditplatform.ErrorCodeThrottled, Retryable: true, Message: "aliyun throttled"}
	}
	if status >= 500 {
		return &auditplatform.ProviderError{Code: auditplatform.ErrorCodeProviderTemporary, Retryable: true, Message: fmt.Sprintf("aliyun provider temporary error: %d", status)}
	}
	return &auditplatform.ProviderError{Code: auditplatform.ErrorCodeInvalidRequest, Message: fmt.Sprintf("aliyun invalid request: %d", status)}
}

func classifyProviderError(err error) *auditplatform.ProviderError {
	if err == nil {
		return nil
	}
	var providerErr *auditplatform.ProviderError
	if errors.As(err, &providerErr) {
		return providerErr
	}
	var netErr net.Error
	if errors.As(err, &netErr) && netErr.Timeout() {
		return &auditplatform.ProviderError{Code: auditplatform.ErrorCodeTimeout, Retryable: true, Message: "aliyun request timeout", Err: err}
	}
	var sdkErr *tea.SDKError
	if errors.As(err, &sdkErr) {
		code := strings.ToLower(tea.StringValue(sdkErr.Code))
		switch {
		case strings.Contains(code, "throttl") || strings.Contains(code, "qps") || strings.Contains(code, "toomanyrequests"):
			return &auditplatform.ProviderError{Code: auditplatform.ErrorCodeThrottled, Retryable: true, Message: "aliyun throttled", Err: err}
		case strings.Contains(code, "invalidaccesskey") || strings.Contains(code, "signature") || strings.Contains(code, "unauthorized"):
			return &auditplatform.ProviderError{Code: auditplatform.ErrorCodeAuthentication, Message: "aliyun authentication error", Err: err}
		case strings.Contains(code, "forbidden") || strings.Contains(code, "permission") || strings.Contains(code, "nopermission"):
			return &auditplatform.ProviderError{Code: auditplatform.ErrorCodePermission, Message: "aliyun permission error", Err: err}
		case strings.Contains(code, "invalid") || strings.Contains(code, "badrequest"):
			return &auditplatform.ProviderError{Code: auditplatform.ErrorCodeInvalidRequest, Message: "aliyun invalid request", Err: err}
		}
	}
	return &auditplatform.ProviderError{Code: auditplatform.ErrorCodeNetwork, Retryable: true, Message: "aliyun network error", Err: err}
}

var _ auditplatform.Provider = (*AliyunAuditClient)(nil)
