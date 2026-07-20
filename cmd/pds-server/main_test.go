package main

import (
	"context"
	"testing"
)

func TestNewServiceUsesMemoryStoreWithoutDatabaseURL(t *testing.T) {
	service, closeStore, err := newService(context.Background(), "")
	if err != nil {
		t.Fatalf("newService returned an error: %v", err)
	}
	defer closeStore()
	if service == nil {
		t.Fatal("newService returned a nil service")
	}
}

func TestNewServiceRejectsUnavailablePostgres(t *testing.T) {
	service, closeStore, err := newService(
		context.Background(),
		"postgres://cargoos:cargoos@127.0.0.1:1/cargoos?sslmode=disable&connect_timeout=1",
	)
	defer closeStore()
	if err == nil {
		t.Fatal("newService accepted an unavailable PostgreSQL server")
	}
	if service != nil {
		t.Fatal("newService returned a service after connection failure")
	}
}
