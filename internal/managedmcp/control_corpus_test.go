package managedmcp

import (
	"encoding/json"
	"os"
	"testing"
)

func TestCanonicalControlCorpus(t *testing.T) {
	body, err := os.ReadFile("../../testdata/managed-control-v1.json")
	if err != nil {
		t.Fatal(err)
	}
	var corpus struct {
		Controls []struct {
			Name   string          `json:"name"`
			Accept bool            `json:"accept"`
			Value  json.RawMessage `json:"value"`
			Digest string          `json:"control_digest"`
		} `json:"controls"`
	}
	if json.Unmarshal(body, &corpus) != nil || len(corpus.Controls) < 10 {
		t.Fatal("invalid control corpus")
	}
	for _, sample := range corpus.Controls {
		t.Run(sample.Name, func(t *testing.T) {
			c, err := DecodeControl(sample.Value)
			if !sample.Accept {
				if err == nil {
					t.Fatal("invalid control accepted")
				}
				return
			}
			if err != nil || ControlFingerprint(c) != sample.Digest {
				t.Fatal("canonical control mismatch", err)
			}
		})
	}
}
