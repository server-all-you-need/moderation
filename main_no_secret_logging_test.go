package main

import (
	"os"
	"strings"
	"testing"
)

func TestMainDoesNotDumpRuntimeConfig(t *testing.T) {
	source, err := os.ReadFile("main.go")
	if err != nil {
		t.Fatalf("read main.go: %v", err)
	}

	content := string(source)
	for _, marker := range []string{
		"json.MarshalIndent(cfg",
		"应用最终将使用以下配置",
		"ContentReviewer",
		"StartConsumerGroupWithRecorder",
		"NewAuditProcessorService",
		"AdminAudit",
	} {
		if strings.Contains(content, marker) {
			t.Fatalf("main.go must not dump full runtime config; found marker %q", marker)
		}
	}
}
