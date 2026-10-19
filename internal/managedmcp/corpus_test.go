package managedmcp

import (
	"encoding/json"
	"os"
	"testing"
)

func TestCanonicalManagedRequestCorpus(t *testing.T) {
	body, err := os.ReadFile("../../testdata/managed-mcp-v1.json")
	if err != nil {
		t.Fatal(err)
	}
	var corpus struct {
		Requests []struct {
			Name   string          `json:"name"`
			Accept bool            `json:"accept"`
			Value  json.RawMessage `json:"value"`
			Digest string          `json:"request_digest"`
			ID     string          `json:"id"`
		} `json:"requests"`
	}
	if err = json.Unmarshal(body, &corpus); err != nil {
		t.Fatal(err)
	}
	for _, c := range corpus.Requests {
		t.Run(c.Name, func(t *testing.T) {
			value, err := DecodeRequest(c.Value)
			if !c.Accept {
				if err == nil {
					t.Fatal("rejected owner shape was accepted")
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if fingerprint(value) != c.Digest || requestID(value) != c.ID {
				t.Fatal("owner fingerprint differs from canonical JavaScript consumer")
			}
		})
	}
}
