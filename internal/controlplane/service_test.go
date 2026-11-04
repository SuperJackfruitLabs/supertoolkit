package controlplane

import (
	"testing"
	"time"
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
