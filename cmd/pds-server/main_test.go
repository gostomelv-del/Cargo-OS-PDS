package main

import (
	"context"
	"errors"
	"testing"

	"cargoos/evidence"
	"cargoos/pds"
)

func TestNewServiceUsesMemoryStoreWithoutDatabaseURL(t *testing.T) {
	service, evidenceService, policyResolver, evidenceQualifier, ruleExecutor, readiness, closeStore, err := newService(
		context.Background(), "", "cargoos-pds.test",
	)
	if err != nil {
		t.Fatalf("newService returned an error: %v", err)
	}
	defer closeStore()
	if service == nil {
		t.Fatal("newService returned a nil service")
	}
	if evidenceService == nil {
		t.Fatal("newService returned a nil Evidence service")
	}
	if policyResolver == nil {
		t.Fatal("newService returned a nil policy resolver")
	}
	if evidenceQualifier == nil {
		t.Fatal("newService returned a nil Evidence Qualification service")
	}
	if ruleExecutor == nil {
		t.Fatal("newService returned a nil Rule Execution service")
	}
	if readiness == nil || readiness.Check(context.Background()) != nil {
		t.Fatal("in-memory service should be ready")
	}
}

func TestNewRuleExecutionServiceRequiresPolicyVersionReader(t *testing.T) {
	evidenceService, err := evidence.NewService(
		evidence.NewMemoryRepository(),
		evidence.ServiceConfig{SchemaVersion: "evidence.v1", RuntimeVersion: "cargoos-pds.test"},
	)
	if err != nil {
		t.Fatal(err)
	}
	executor, err := newRuleExecutionService(pds.NewService(nil), evidenceService, nil)
	if !errors.Is(err, pds.ErrPolicyVersionReaderRequired) {
		t.Fatalf("got %v, want %v", err, pds.ErrPolicyVersionReaderRequired)
	}
	if executor != nil {
		t.Fatal("newRuleExecutionService returned an executor without a Policy Version Reader")
	}
}

func TestNewServiceRejectsUnavailablePostgres(t *testing.T) {
	service, evidenceService, policyResolver, evidenceQualifier, ruleExecutor, readiness, closeStore, err := newService(
		context.Background(),
		"postgres://cargoos:cargoos@127.0.0.1:1/cargoos?sslmode=disable&connect_timeout=1",
		"cargoos-pds.test",
	)
	defer closeStore()
	if err == nil {
		t.Fatal("newService accepted an unavailable PostgreSQL server")
	}
	if service != nil {
		t.Fatal("newService returned a service after connection failure")
	}
	if evidenceService != nil {
		t.Fatal("newService returned Evidence service after connection failure")
	}
	if policyResolver != nil {
		t.Fatal("newService returned policy resolver after connection failure")
	}
	if evidenceQualifier != nil {
		t.Fatal("newService returned Evidence Qualification service after connection failure")
	}
	if ruleExecutor != nil {
		t.Fatal("newService returned Rule Execution service after connection failure")
	}
	if readiness != nil {
		t.Fatal("newService returned readiness after connection failure")
	}
}
