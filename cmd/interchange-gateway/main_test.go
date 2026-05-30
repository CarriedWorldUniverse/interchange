package main

import "testing"

func TestParseRoutes(t *testing.T) {
	got, err := parseRoutes("/herald=http://herald:8099, /ledger=http://ledger:8080 ,/cairn=http://cairn:3000")
	if err != nil {
		t.Fatalf("parseRoutes: %v", err)
	}
	want := map[string]string{
		"/herald": "http://herald:8099",
		"/ledger": "http://ledger:8080",
		"/cairn":  "http://cairn:3000",
	}
	if len(got) != len(want) {
		t.Fatalf("got %d routes, want %d: %v", len(got), len(want), got)
	}
	for k, v := range want {
		if got[k] != v {
			t.Errorf("route %q = %q, want %q", k, got[k], v)
		}
	}
}

func TestParseRoutes_Empty(t *testing.T) {
	got, err := parseRoutes("")
	if err != nil || len(got) != 0 {
		t.Fatalf("empty routes: got %v err %v", got, err)
	}
}

func TestParseRoutes_Bad(t *testing.T) {
	for _, bad := range []string{"noequals", "=nobackend", "/prefix="} {
		if _, err := parseRoutes(bad); err == nil {
			t.Errorf("parseRoutes(%q) should error", bad)
		}
	}
}
