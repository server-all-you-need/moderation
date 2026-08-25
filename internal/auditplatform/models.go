package auditplatform

import (
	"context"
	"fmt"
	"net"
	"net/url"
	"strings"
	"unicode/utf8"
)

type ContentType string

const (
	ContentTypeText  ContentType = "text"
	ContentTypeImage ContentType = "image"
)

type Decision string

const (
	DecisionPass   Decision = "pass"
	DecisionReview Decision = "review"
	DecisionBlock  Decision = "block"
)

type RiskLevel string

const (
	RiskLevelNone   RiskLevel = "none"
	RiskLevelLow    RiskLevel = "low"
	RiskLevelMedium RiskLevel = "medium"
	RiskLevelHigh   RiskLevel = "high"
)

type Policy string

const (
	PolicyTextComment  Policy = "text.comment"
	PolicyTextNickname Policy = "text.nickname"
	PolicyTextGeneral  Policy = "text.general"
	PolicyImageComment Policy = "image.comment"
	PolicyImageAvatar  Policy = "image.avatar"
	PolicyImageGeneral Policy = "image.general"
)

type PolicySpec struct {
	ContentType       ContentType
	ProviderService   string
	MaxTextCodePoints int
}

var policySpecs = map[Policy]PolicySpec{
	PolicyTextComment:  {ContentType: ContentTypeText, ProviderService: "comment_detection_pro", MaxTextCodePoints: 600},
	PolicyTextNickname: {ContentType: ContentTypeText, ProviderService: "nickname_detection_pro", MaxTextCodePoints: 600},
	PolicyTextGeneral:  {ContentType: ContentTypeText, ProviderService: "ugc_moderation_byllm", MaxTextCodePoints: 2000},
	PolicyImageComment: {ContentType: ContentTypeImage, ProviderService: "postImageCheck"},
	PolicyImageAvatar:  {ContentType: ContentTypeImage, ProviderService: "profilePhotoCheck"},
	PolicyImageGeneral: {ContentType: ContentTypeImage, ProviderService: "baselineCheck_pro"},
}

func LookupPolicy(policy Policy) (PolicySpec, bool) {
	spec, ok := policySpecs[policy]
	return spec, ok
}

type ModerationInput struct {
	ClientItemID string      `json:"client_item_id"`
	ContentType  ContentType `json:"content_type"`
	Policy       Policy      `json:"policy"`
	Text         string      `json:"text,omitempty"`
	ImageURL     string      `json:"image_url,omitempty"`
}

func (in ModerationInput) Validate() error {
	if err := validateClientItemID(in.ClientItemID); err != nil {
		return err
	}
	spec, ok := LookupPolicy(in.Policy)
	if !ok {
		return fmt.Errorf("unknown policy %q", in.Policy)
	}
	if in.ContentType != ContentTypeText && in.ContentType != ContentTypeImage {
		return fmt.Errorf("unsupported content_type %q", in.ContentType)
	}
	if spec.ContentType != in.ContentType {
		return fmt.Errorf("policy %q does not match content_type %q", in.Policy, in.ContentType)
	}

	hasText := in.Text != ""
	hasImageURL := in.ImageURL != ""
	if hasText == hasImageURL {
		return fmt.Errorf("exactly one of text or image_url is required")
	}

	switch in.ContentType {
	case ContentTypeText:
		if !hasText {
			return fmt.Errorf("text content requires text")
		}
		if utf8.RuneCountInString(in.Text) > spec.MaxTextCodePoints {
			return fmt.Errorf("text exceeds %d Unicode code points", spec.MaxTextCodePoints)
		}
	case ContentTypeImage:
		if !hasImageURL {
			return fmt.Errorf("image content requires image_url")
		}
		if err := ValidatePublicHTTPSImageURL(in.ImageURL); err != nil {
			return err
		}
	}
	return nil
}

func ValidatePublicHTTPSImageURL(raw string) error {
	parsed, err := url.Parse(raw)
	if err != nil {
		return fmt.Errorf("invalid image_url: %w", err)
	}
	if parsed.Scheme != "https" {
		return fmt.Errorf("image_url must use https")
	}
	if parsed.User != nil {
		return fmt.Errorf("image_url must not contain userinfo")
	}
	host := parsed.Hostname()
	if host == "" {
		return fmt.Errorf("image_url must have a hostname")
	}
	if strings.Contains(parsed.Host, ":") && parsed.Port() == "" {
		return fmt.Errorf("image_url has invalid explicit port")
	}
	if port := parsed.Port(); port != "" && port != "443" {
		return fmt.Errorf("image_url must not use non-443 explicit port")
	}
	normalizedHost := strings.ToLower(strings.TrimSuffix(host, "."))
	if ip := net.ParseIP(normalizedHost); ip != nil {
		return fmt.Errorf("image_url hostname must not be an IP literal")
	}
	if normalizedHost == "localhost" || strings.HasSuffix(normalizedHost, ".local") || strings.HasSuffix(normalizedHost, ".internal") {
		return fmt.Errorf("image_url hostname must be public")
	}
	if !isDNSHostname(normalizedHost) {
		return fmt.Errorf("image_url must have a DNS hostname")
	}
	return nil
}

func isDNSHostname(host string) bool {
	if host == "" || len(host) > 253 {
		return false
	}
	for _, label := range strings.Split(host, ".") {
		if label == "" || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for _, r := range label {
			if r >= 'a' && r <= 'z' || r >= '0' && r <= '9' || r == '-' {
				continue
			}
			return false
		}
	}
	return true
}

func validateClientItemID(id string) error {
	if id == "" || len(id) > 64 {
		return fmt.Errorf("client_item_id must be 1-64 characters")
	}
	for _, r := range id {
		if r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || r == '.' || r == '_' || r == '-' {
			continue
		}
		return fmt.Errorf("client_item_id contains invalid character")
	}
	return nil
}

type LabelEntry struct {
	Label       string   `json:"label"`
	Confidence  float64  `json:"confidence,omitempty"`
	Description string   `json:"description,omitempty"`
	RiskWords   []string `json:"risk_words,omitempty"`
}

type ModerationResult struct {
	ClientItemID      string       `json:"client_item_id"`
	Decision          Decision     `json:"decision"`
	RiskLevel         RiskLevel    `json:"risk_level"`
	ProviderName      string       `json:"provider_name"`
	ProviderRequestID string       `json:"provider_request_id,omitempty"`
	ProviderDataID    string       `json:"provider_data_id,omitempty"`
	Labels            []LabelEntry `json:"labels,omitempty"`
}

type Provider interface {
	Moderate(ctx context.Context, input ModerationInput) (ModerationResult, error)
	Name() string
}

const (
	ErrorCodeInvalidInput      = "invalid_input"
	ErrorCodeProviderResponse  = "provider_response"
	ErrorCodeAuthentication    = "authentication"
	ErrorCodePermission        = "permission"
	ErrorCodeInvalidRequest    = "invalid_request"
	ErrorCodeTimeout           = "timeout"
	ErrorCodeNetwork           = "network"
	ErrorCodeThrottled         = "throttled"
	ErrorCodeProviderTemporary = "provider_temporary"
)

type ProviderError struct {
	Code      string
	Retryable bool
	Message   string
	Err       error
}

func (e *ProviderError) Error() string {
	if e == nil {
		return ""
	}
	if e.Message != "" {
		return e.Message
	}
	if e.Err != nil {
		return e.Err.Error()
	}
	return e.Code
}

func (e *ProviderError) Unwrap() error {
	if e == nil {
		return nil
	}
	return e.Err
}

func NormalizeRiskLevel(raw string) (RiskLevel, Decision, error) {
	switch RiskLevel(strings.ToLower(strings.TrimSpace(raw))) {
	case RiskLevelNone:
		return RiskLevelNone, DecisionPass, nil
	case RiskLevelLow:
		return RiskLevelLow, DecisionPass, nil
	case RiskLevelMedium:
		return RiskLevelMedium, DecisionReview, nil
	case RiskLevelHigh:
		return RiskLevelHigh, DecisionBlock, nil
	default:
		return "", "", &ProviderError{Code: ErrorCodeProviderResponse, Message: "unknown or missing provider risk level"}
	}
}
