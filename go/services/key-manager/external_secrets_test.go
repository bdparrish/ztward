package key_manager

import (
	"context"
	"testing"
)

func TestExtractFieldFromJSON_EmptyField(t *testing.T) {
	// Empty field returns the full payload unchanged.
	payload := `{"key": "value"}`
	got, err := extractFieldFromJSON(payload, "")
	if err != nil {
		t.Fatalf("extractFieldFromJSON('') error = %v", err)
	}
	if got != payload {
		t.Errorf("expected full payload, got %q", got)
	}
}

func TestExtractFieldFromJSON_ValidField(t *testing.T) {
	payload := `{"username": "alice", "password": "secret"}`
	got, err := extractFieldFromJSON(payload, "username")
	if err != nil {
		t.Fatalf("extractFieldFromJSON error = %v", err)
	}
	if got != "alice" {
		t.Errorf("expected 'alice', got %q", got)
	}
}

func TestExtractFieldFromJSON_InvalidJSON(t *testing.T) {
	_, err := extractFieldFromJSON("not-json", "field")
	if err == nil {
		t.Fatal("expected error for invalid JSON")
	}
}

func TestExtractFieldFromJSON_MissingField(t *testing.T) {
	_, err := extractFieldFromJSON(`{"other": "value"}`, "missing")
	if err == nil {
		t.Fatal("expected error for missing field")
	}
}

func TestExtractFieldFromJSON_NonStringValue(t *testing.T) {
	_, err := extractFieldFromJSON(`{"count": 42}`, "count")
	if err == nil {
		t.Fatal("expected error when field value is not a string")
	}
}

func TestAWSSecretsManagerFetcher_MissingSecretID(t *testing.T) {
	f := NewAWSSecretsManagerFetcher()
	_, err := f.FetchSecret(context.Background(), "us-east-1", "", "", "", "")
	if err == nil {
		t.Fatal("expected error for empty secretID")
	}
}

func TestAWSSecretsManagerFetcher_MissingRegion(t *testing.T) {
	f := NewAWSSecretsManagerFetcher()
	_, err := f.FetchSecret(context.Background(), "", "", "my-secret", "", "")
	if err == nil {
		t.Fatal("expected error for empty region")
	}
}
