package main

import (
	"context"
	"testing"
)

func TestNewServiceUsesMemoryStoreWithoutDatabaseURL(t *testing.T) {
	service, evidenceService, readiness, closeStore, err := newService(
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
	if readiness == nil || readiness.Check(context.Background()) != nil {
		t.Fatal("in-memory service should be ready")
	}
}

func TestNewServiceRejectsUnavailablePostgres(t *testing.T) {
	service, evidenceService, readiness, closeStore, err := newService(
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
	if readiness != nil {
		t.Fatal("newService returned readiness after connection failure")
	}
}
