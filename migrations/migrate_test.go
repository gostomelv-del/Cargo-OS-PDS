package migrations

import (
	"context"
	"errors"
	"reflect"
	"strings"
	"testing"
)

func TestApplyRequiresDatabase(t *testing.T) {
	if err := Apply(context.Background(), nil); !errors.Is(err, ErrDatabaseRequired) {
		t.Fatalf("expected ErrDatabaseRequired, got %v", err)
	}
}

func TestEmbeddedMigrationNamesAreSorted(t *testing.T) {
	names, err := embeddedMigrationNames()
	if err != nil {
		t.Fatal(err)
	}
	want := []string{
		"0001_evaluation_persistence.sql", "0002_evidence_objects.sql",
		"0003_policy_versions.sql", "0004_policy_signatures.sql",
	}
	if !reflect.DeepEqual(names, want) {
		t.Fatalf("expected %v, got %v", want, names)
	}
}

func TestWithoutTransactionWrapper(t *testing.T) {
	contents := "BEGIN;\n\nCREATE TABLE example (id BIGINT);\n\nCOMMIT;"
	got := withoutTransactionWrapper(contents)
	if strings.Contains(got, "BEGIN;") || strings.Contains(got, "COMMIT;") {
		t.Fatalf("transaction wrapper was not removed: %q", got)
	}
	if !strings.Contains(got, "CREATE TABLE example") {
		t.Fatalf("migration body was removed: %q", got)
	}
}

func TestWithoutTransactionWrapperPreservesUnwrappedSQL(t *testing.T) {
	contents := "CREATE TABLE example (id BIGINT);"
	if got := withoutTransactionWrapper(contents); got != contents {
		t.Fatalf("expected %q, got %q", contents, got)
	}
}
