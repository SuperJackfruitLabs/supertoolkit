package controlplane

import (
	"context"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/SuperJackfruitLabs/supertoolkit/internal/credential"
	"github.com/SuperJackfruitLabs/supertoolkit/internal/policy"
)

func TestPublisherAloneUsesManagedOneDispatchClient(t *testing.T) {
	publisher := effectHTTPClient("publish")
	ordinary := effectHTTPClient("serve")
	if publisher.CheckRedirect == nil || publisher.Timeout != 30*time.Second {
		t.Fatalf("publisher client lacks managed transport semantics: timeout=%v redirects=%t", publisher.Timeout, publisher.CheckRedirect != nil)
	}
	if ordinary.Timeout != 60*time.Second || ordinary.CheckRedirect != nil {
		t.Fatalf("ordinary control-plane client changed semantics: timeout=%v redirects=%t", ordinary.Timeout, ordinary.CheckRedirect != nil)
	}
}

func TestNonPublisherPerformRefusesNativeOnlyService(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "supertoolkit.yaml")
	if err := os.WriteFile(path, []byte("workspace: test\nservices:\n  superpipeline-approvals-read:\n    scopes: []\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, err := policy.Load(path)
	if err != nil {
		t.Fatal(err)
	}
	store, err := credential.OpenStore(filepath.Join(dir, "credentials"), "fixture")
	if err != nil {
		t.Fatal(err)
	}
	service, err := New(cfg, store, filepath.Join(dir, "state"), "serve", "test")
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	req, _ := http.NewRequestWithContext(ctx, http.MethodPost, "https://app.superpipeline.dev/v1/boards/b/approval-subjects/s/verify", nil)
	resp, err := service.Perform(ctx, "superpipeline-approvals-read", req)
	if resp != nil {
		defer resp.Body.Close()
	}
	if err == nil || !strings.Contains(err.Error(), "native publisher") {
		t.Fatalf("Perform error = %v; want native-only refusal", err)
	}
}
