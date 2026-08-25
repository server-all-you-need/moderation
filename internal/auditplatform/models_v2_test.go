package auditplatform

import (
	"context"
	"errors"
	"strings"
	"testing"
)

func TestPolicySpecsUseRequiredProviderServicesAndTextLimits(t *testing.T) {
	tests := []struct {
		policy  Policy
		content ContentType
		service string
		limit   int
	}{
		{PolicyTextComment, ContentTypeText, "comment_detection_pro", 600},
		{PolicyTextNickname, ContentTypeText, "nickname_detection_pro", 600},
		{PolicyTextGeneral, ContentTypeText, "ugc_moderation_byllm", 2000},
		{PolicyImageComment, ContentTypeImage, "postImageCheck", 0},
		{PolicyImageAvatar, ContentTypeImage, "profilePhotoCheck", 0},
		{PolicyImageGeneral, ContentTypeImage, "baselineCheck_pro", 0},
	}

	for _, tt := range tests {
		t.Run(string(tt.policy), func(t *testing.T) {
			spec, ok := LookupPolicy(tt.policy)
			if !ok {
				t.Fatalf("LookupPolicy(%q) returned !ok", tt.policy)
			}
			if spec.ContentType != tt.content {
				t.Fatalf("content type = %q, want %q", spec.ContentType, tt.content)
			}
			if spec.ProviderService != tt.service {
				t.Fatalf("provider service = %q, want %q", spec.ProviderService, tt.service)
			}
			if spec.MaxTextCodePoints != tt.limit {
				t.Fatalf("text limit = %d, want %d", spec.MaxTextCodePoints, tt.limit)
			}
		})
	}
}

func TestModerationInputValidationRejectsInvalidContentCombinations(t *testing.T) {
	tests := []struct {
		name  string
		input ModerationInput
	}{
		{
			name: "text input cannot also include image URL",
			input: ModerationInput{
				ClientItemID: "post.1",
				ContentType:  ContentTypeText,
				Policy:       PolicyTextComment,
				Text:         "hello",
				ImageURL:     "https://cdn.example.com/a.png",
			},
		},
		{
			name: "text input requires text",
			input: ModerationInput{
				ClientItemID: "post.1",
				ContentType:  ContentTypeText,
				Policy:       PolicyTextComment,
			},
		},
		{
			name: "image input requires image URL",
			input: ModerationInput{
				ClientItemID: "post.1",
				ContentType:  ContentTypeImage,
				Policy:       PolicyImageComment,
			},
		},
		{
			name: "text policy cannot be used with image content type",
			input: ModerationInput{
				ClientItemID: "post.1",
				ContentType:  ContentTypeImage,
				Policy:       PolicyTextComment,
				ImageURL:     "https://cdn.example.com/a.png",
			},
		},
		{
			name: "image policy cannot be used with text content type",
			input: ModerationInput{
				ClientItemID: "post.1",
				ContentType:  ContentTypeText,
				Policy:       PolicyImageComment,
				Text:         "hello",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := tt.input.Validate(); err == nil {
				t.Fatal("Validate() returned nil, want error")
			}
		})
	}
}

func TestModerationInputValidationAcceptsExactTextLimitByUnicodeCodePoints(t *testing.T) {
	input := ModerationInput{
		ClientItemID: "post_1",
		ContentType:  ContentTypeText,
		Policy:       PolicyTextComment,
		Text:         strings.Repeat("界", 600),
	}
	if err := input.Validate(); err != nil {
		t.Fatalf("Validate() returned error at exact limit: %v", err)
	}

	input.Text += "界"
	if err := input.Validate(); err == nil {
		t.Fatal("Validate() returned nil above text limit, want error")
	}
}

func TestClientItemIDValidation(t *testing.T) {
	valid := []string{"a", "A-Z_09.1", strings.Repeat("a", 64)}
	for _, id := range valid {
		input := validTextInput()
		input.ClientItemID = id
		if err := input.Validate(); err != nil {
			t.Fatalf("Validate() rejected valid client_item_id %q: %v", id, err)
		}
	}

	invalid := []string{"", strings.Repeat("a", 65), "has space", "中文", "slash/id"}
	for _, id := range invalid {
		input := validTextInput()
		input.ClientItemID = id
		if err := input.Validate(); err == nil {
			t.Fatalf("Validate() accepted invalid client_item_id %q", id)
		}
	}
}

func TestImageURLValidationRequiresPublicHTTPSDNSHost(t *testing.T) {
	valid := []string{
		"https://cdn.example.com/a.png",
		"https://cdn.example.com:443/a.png",
	}
	for _, imageURL := range valid {
		input := validImageInput()
		input.ImageURL = imageURL
		if err := input.Validate(); err != nil {
			t.Fatalf("Validate() rejected valid image_url %q: %v", imageURL, err)
		}
	}

	invalid := []string{
		"http://cdn.example.com/a.png",
		"https://user:pass@cdn.example.com/a.png",
		"https://cdn.example.com:8443/a.png",
		"https://127.0.0.1/a.png",
		"https://[::1]/a.png",
		"https://localhost/a.png",
		"https://image.local/a.png",
		"https://image.internal/a.png",
		"https:///a.png",
	}
	for _, imageURL := range invalid {
		input := validImageInput()
		input.ImageURL = imageURL
		if err := input.Validate(); err == nil {
			t.Fatalf("Validate() accepted invalid image_url %q", imageURL)
		}
	}
}

func TestNormalizeRiskLevelMapsKnownProviderRisks(t *testing.T) {
	tests := []struct {
		raw      string
		risk     RiskLevel
		decision Decision
	}{
		{"none", RiskLevelNone, DecisionPass},
		{"low", RiskLevelLow, DecisionPass},
		{"medium", RiskLevelMedium, DecisionReview},
		{"high", RiskLevelHigh, DecisionBlock},
	}

	for _, tt := range tests {
		t.Run(tt.raw, func(t *testing.T) {
			risk, decision, err := NormalizeRiskLevel(tt.raw)
			if err != nil {
				t.Fatalf("NormalizeRiskLevel(%q) returned error: %v", tt.raw, err)
			}
			if risk != tt.risk || decision != tt.decision {
				t.Fatalf("NormalizeRiskLevel(%q) = (%q, %q), want (%q, %q)", tt.raw, risk, decision, tt.risk, tt.decision)
			}
		})
	}
}

func TestNormalizeRiskLevelRejectsMissingOrUnknownRisk(t *testing.T) {
	for _, raw := range []string{"", "unknown"} {
		_, _, err := NormalizeRiskLevel(raw)
		if err == nil {
			t.Fatalf("NormalizeRiskLevel(%q) returned nil error", raw)
		}
		var providerErr *ProviderError
		if !errors.As(err, &providerErr) {
			t.Fatalf("NormalizeRiskLevel(%q) error = %T, want *ProviderError", raw, err)
		}
		if providerErr.Code != ErrorCodeProviderResponse || providerErr.Retryable {
			t.Fatalf("ProviderError = code %q retryable %v, want %q false", providerErr.Code, providerErr.Retryable, ErrorCodeProviderResponse)
		}
	}
}

func TestProviderErrorCarriesStableCodeAndRetryableFlag(t *testing.T) {
	err := &ProviderError{Code: ErrorCodeThrottled, Retryable: true, Message: "qps exceeded"}
	if !err.Retryable {
		t.Fatal("Retryable = false, want true")
	}
	if err.Code != "throttled" {
		t.Fatalf("Code = %q, want throttled", err.Code)
	}
	if err.Error() == "" {
		t.Fatal("Error() returned empty string")
	}
}

func TestProviderInterfaceUsesNormalizedInputAndResult(t *testing.T) {
	var _ Provider = providerFunc(func(context.Context, ModerationInput) (ModerationResult, error) {
		return ModerationResult{
			ClientItemID:      "post.1",
			Decision:          DecisionReview,
			RiskLevel:         RiskLevelMedium,
			ProviderName:      "fake",
			ProviderRequestID: "req-1",
			ProviderDataID:    "post.1",
		}, nil
	})
}

func validTextInput() ModerationInput {
	return ModerationInput{
		ClientItemID: "post.1",
		ContentType:  ContentTypeText,
		Policy:       PolicyTextComment,
		Text:         "hello",
	}
}

func validImageInput() ModerationInput {
	return ModerationInput{
		ClientItemID: "img-1",
		ContentType:  ContentTypeImage,
		Policy:       PolicyImageComment,
		ImageURL:     "https://cdn.example.com/a.png",
	}
}

type providerFunc func(context.Context, ModerationInput) (ModerationResult, error)

func (f providerFunc) Moderate(ctx context.Context, input ModerationInput) (ModerationResult, error) {
	return f(ctx, input)
}

func (f providerFunc) Name() string {
	return "fake"
}
