package main

import "testing"

func TestRunRequiresDatabaseURL(t *testing.T) {
	t.Setenv("PDS_DATABASE_URL", "")
	if err := run(); err == nil {
		t.Fatal("run accepted an empty PDS_DATABASE_URL")
	}
}
