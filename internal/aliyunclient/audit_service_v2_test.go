package aliyunclient

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"testing"
	"time"

	green "github.com/alibabacloud-go/green-20220302/v3/client"
	"github.com/alibabacloud-go/tea/dara"
	"github.com/alibabacloud-go/tea/tea"

	"github.com/Xushengqwer/post_audit/internal/auditplatform"
)

func TestModerateTextUsesTextModerationPlusRequestAndNormalizesResponse(t *testing.T) {
	fake := &fakeGreenSDK{
		textResponse: (&green.TextModerationPlusResponse{}).
			SetStatusCode(200).
			SetBody((&green.TextModerationPlusResponseBody{}).
				SetCode(200).
				SetRequestId("req-text").
				SetData((&green.TextModerationPlusResponseBodyData{}).
					SetDataId("client.1").
					SetRiskLevel("medium").
					SetResult([]*green.TextModerationPlusResponseBodyDataResult{
						(&green.TextModerationPlusResponseBodyDataResult{}).
							SetLabel("spam").
							SetConfidence(82.5).
							SetDescription("广告").
							SetRiskWords("foo,bar"),
					}))),
	}
	client := newAliyunAuditClientWithSDK(fake, 1500*time.Millisecond, 2500*time.Millisecond)

	result, err := client.Moderate(context.Background(), auditplatform.ModerationInput{
		ClientItemID: "client.1",
		ContentType:  auditplatform.ContentTypeText,
		Policy:       auditplatform.PolicyTextComment,
		Text:         "hello",
	})
	if err != nil {
		t.Fatalf("Moderate() returned error: %v", err)
	}

	if fake.textCalls != 1 || fake.imageCalls != 0 {
		t.Fatalf("textCalls=%d imageCalls=%d, want 1 and 0", fake.textCalls, fake.imageCalls)
	}
	if got := tea.StringValue(fake.textRequest.Service); got != "comment_detection_pro" {
		t.Fatalf("text service = %q, want comment_detection_pro", got)
	}
	var params map[string]string
	if err := json.Unmarshal([]byte(tea.StringValue(fake.textRequest.ServiceParameters)), &params); err != nil {
		t.Fatalf("ServiceParameters is not JSON: %v", err)
	}
	if params["content"] != "hello" || params["dataId"] != "client.1" {
		t.Fatalf("ServiceParameters = %#v, want content and dataId", params)
	}
	if fake.textRuntime == nil || tea.IntValue(fake.textRuntime.ConnectTimeout) != 1500 || tea.IntValue(fake.textRuntime.ReadTimeout) != 2500 {
		t.Fatalf("runtime timeouts = %#v, want connect=1500 read=2500", fake.textRuntime)
	}
	if result.ClientItemID != "client.1" ||
		result.ProviderDataID != "client.1" ||
		result.ProviderRequestID != "req-text" ||
		result.ProviderName != "aliyun" ||
		result.RiskLevel != auditplatform.RiskLevelMedium ||
		result.Decision != auditplatform.DecisionReview {
		t.Fatalf("normalized result = %#v", result)
	}
	if len(result.Labels) != 1 {
		t.Fatalf("labels len = %d, want 1", len(result.Labels))
	}
	label := result.Labels[0]
	if label.Label != "spam" || label.Confidence != 82.5 || label.Description != "广告" {
		t.Fatalf("label = %#v", label)
	}
	if len(label.RiskWords) != 2 || label.RiskWords[0] != "foo" || label.RiskWords[1] != "bar" {
		t.Fatalf("risk words = %#v, want [foo bar]", label.RiskWords)
	}
}

func TestModerateImageUsesImageModerationRequestAndNormalizesResponse(t *testing.T) {
	fake := &fakeGreenSDK{
		imageResponse: (&green.ImageModerationResponse{}).
			SetStatusCode(200).
			SetBody((&green.ImageModerationResponseBody{}).
				SetCode(200).
				SetRequestId("req-image").
				SetData((&green.ImageModerationResponseBodyData{}).
					SetDataId("img-1").
					SetRiskLevel("high").
					SetResult([]*green.ImageModerationResponseBodyDataResult{
						(&green.ImageModerationResponseBodyDataResult{}).
							SetLabel("violent").
							SetConfidence(91.25).
							SetDescription("暴力").
							SetRiskLevel("high"),
					}))),
	}
	client := newAliyunAuditClientWithSDK(fake, time.Second, 2*time.Second)

	result, err := client.Moderate(context.Background(), auditplatform.ModerationInput{
		ClientItemID: "img-1",
		ContentType:  auditplatform.ContentTypeImage,
		Policy:       auditplatform.PolicyImageAvatar,
		ImageURL:     "https://cdn.example.com/avatar.png",
	})
	if err != nil {
		t.Fatalf("Moderate() returned error: %v", err)
	}

	if fake.imageCalls != 1 || fake.textCalls != 0 {
		t.Fatalf("imageCalls=%d textCalls=%d, want 1 and 0", fake.imageCalls, fake.textCalls)
	}
	if got := tea.StringValue(fake.imageRequest.Service); got != "profilePhotoCheck" {
		t.Fatalf("image service = %q, want profilePhotoCheck", got)
	}
	var params map[string]string
	if err := json.Unmarshal([]byte(tea.StringValue(fake.imageRequest.ServiceParameters)), &params); err != nil {
		t.Fatalf("ServiceParameters is not JSON: %v", err)
	}
	if params["imageUrl"] != "https://cdn.example.com/avatar.png" || params["dataId"] != "img-1" {
		t.Fatalf("ServiceParameters = %#v, want imageUrl and dataId", params)
	}
	if result.Decision != auditplatform.DecisionBlock || result.RiskLevel != auditplatform.RiskLevelHigh {
		t.Fatalf("result decision/risk = %q/%q, want block/high", result.Decision, result.RiskLevel)
	}
	if len(result.Labels) != 1 || result.Labels[0].Label != "violent" || result.Labels[0].Confidence != 91.25 {
		t.Fatalf("labels = %#v", result.Labels)
	}
}

func TestModerateClassifiesProviderErrorsRetryability(t *testing.T) {
	tests := []struct {
		name      string
		setup     func(*fakeGreenSDK)
		code      string
		retryable bool
	}{
		{
			name: "timeout is retryable",
			setup: func(fake *fakeGreenSDK) {
				fake.textErr = timeoutError{}
			},
			code:      auditplatform.ErrorCodeTimeout,
			retryable: true,
		},
		{
			name: "throttling is retryable",
			setup: func(fake *fakeGreenSDK) {
				fake.textErr = &tea.SDKError{Code: tea.String("Throttling.User"), Message: tea.String("qps")}
			},
			code:      auditplatform.ErrorCodeThrottled,
			retryable: true,
		},
		{
			name: "http 429 is retryable throttling",
			setup: func(fake *fakeGreenSDK) {
				fake.textResponse = textResponse(429, 200, "req-http-429", "none")
			},
			code:      auditplatform.ErrorCodeThrottled,
			retryable: true,
		},
		{
			name: "provider body 429 is retryable throttling",
			setup: func(fake *fakeGreenSDK) {
				fake.textResponse = textResponse(200, 429, "req-body-429", "none")
			},
			code:      auditplatform.ErrorCodeThrottled,
			retryable: true,
		},
		{
			name: "provider 5xx body code is retryable",
			setup: func(fake *fakeGreenSDK) {
				fake.textResponse = textResponse(200, 503, "req-503", "none")
			},
			code:      auditplatform.ErrorCodeProviderTemporary,
			retryable: true,
		},
		{
			name: "authentication error is permanent",
			setup: func(fake *fakeGreenSDK) {
				fake.textErr = &tea.SDKError{Code: tea.String("InvalidAccessKeyId.NotFound"), Message: tea.String("bad key")}
			},
			code:      auditplatform.ErrorCodeAuthentication,
			retryable: false,
		},
		{
			name: "permission error is permanent",
			setup: func(fake *fakeGreenSDK) {
				fake.textErr = &tea.SDKError{Code: tea.String("Forbidden.RAM"), Message: tea.String("denied")}
			},
			code:      auditplatform.ErrorCodePermission,
			retryable: false,
		},
		{
			name: "invalid request is permanent",
			setup: func(fake *fakeGreenSDK) {
				fake.textResponse = textResponse(200, 400, "req-400", "none")
			},
			code:      auditplatform.ErrorCodeInvalidRequest,
			retryable: false,
		},
		{
			name: "missing body is permanent provider response error",
			setup: func(fake *fakeGreenSDK) {
				fake.textResponse = (&green.TextModerationPlusResponse{}).SetStatusCode(200)
			},
			code:      auditplatform.ErrorCodeProviderResponse,
			retryable: false,
		},
		{
			name: "missing data is permanent provider response error",
			setup: func(fake *fakeGreenSDK) {
				fake.textResponse = (&green.TextModerationPlusResponse{}).SetStatusCode(200).SetBody((&green.TextModerationPlusResponseBody{}).SetCode(200).SetRequestId("req"))
			},
			code:      auditplatform.ErrorCodeProviderResponse,
			retryable: false,
		},
		{
			name: "unknown risk is permanent provider response error",
			setup: func(fake *fakeGreenSDK) {
				fake.textResponse = textResponse(200, 200, "req-risk", "strange")
			},
			code:      auditplatform.ErrorCodeProviderResponse,
			retryable: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fake := &fakeGreenSDK{}
			tt.setup(fake)
			client := newAliyunAuditClientWithSDK(fake, time.Second, time.Second)
			_, err := client.Moderate(context.Background(), auditplatform.ModerationInput{
				ClientItemID: "client.1",
				ContentType:  auditplatform.ContentTypeText,
				Policy:       auditplatform.PolicyTextGeneral,
				Text:         "hello",
			})
			if err == nil {
				t.Fatal("Moderate() returned nil error, want ProviderError")
			}
			var providerErr *auditplatform.ProviderError
			if !errors.As(err, &providerErr) {
				t.Fatalf("error = %T, want *ProviderError", err)
			}
			if providerErr.Code != tt.code || providerErr.Retryable != tt.retryable {
				t.Fatalf("ProviderError = code %q retryable %v, want %q %v", providerErr.Code, providerErr.Retryable, tt.code, tt.retryable)
			}
		})
	}
}

func textResponse(httpStatus, bodyCode int32, requestID, risk string) *green.TextModerationPlusResponse {
	resp := (&green.TextModerationPlusResponse{}).SetStatusCode(httpStatus)
	body := (&green.TextModerationPlusResponseBody{}).SetCode(bodyCode).SetRequestId(requestID)
	if risk != "" {
		body.SetData((&green.TextModerationPlusResponseBodyData{}).SetDataId("client.1").SetRiskLevel(risk))
	}
	return resp.SetBody(body)
}

type fakeGreenSDK struct {
	textCalls     int
	imageCalls    int
	textRequest   *green.TextModerationPlusRequest
	imageRequest  *green.ImageModerationRequest
	textRuntime   *dara.RuntimeOptions
	imageRuntime  *dara.RuntimeOptions
	textResponse  *green.TextModerationPlusResponse
	imageResponse *green.ImageModerationResponse
	textErr       error
	imageErr      error
}

func (f *fakeGreenSDK) TextModerationPlusWithContext(_ context.Context, request *green.TextModerationPlusRequest, runtime *dara.RuntimeOptions) (*green.TextModerationPlusResponse, error) {
	f.textCalls++
	f.textRequest = request
	f.textRuntime = runtime
	return f.textResponse, f.textErr
}

func (f *fakeGreenSDK) ImageModerationWithContext(_ context.Context, request *green.ImageModerationRequest, runtime *dara.RuntimeOptions) (*green.ImageModerationResponse, error) {
	f.imageCalls++
	f.imageRequest = request
	f.imageRuntime = runtime
	return f.imageResponse, f.imageErr
}

type timeoutError struct{}

func (timeoutError) Error() string   { return "timeout" }
func (timeoutError) Timeout() bool   { return true }
func (timeoutError) Temporary() bool { return true }

var _ net.Error = timeoutError{}
