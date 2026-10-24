// Package svc holds the small Xbox services: telemetry sinks, settings
// stubs, profile, social, presence, privacy, notifications and stats.
package svc

import (
	"encoding/json"
	"io"
	"net/http"
)

// Sink accepts telemetry and answers settings fetches with empty documents:
// vortex-events.xboxlive.com, vortex.data.microsoft.com,
// settings.data.microsoft.com and the like. Nothing is stored.
func Sink(w http.ResponseWriter, r *http.Request) {
	io.Copy(io.Discard, io.LimitReader(r.Body, 1<<20))
	switch r.Method {
	case http.MethodGet:
		WriteJSON(w, http.StatusOK, map[string]any{"settings": map[string]any{}})
	default:
		WriteJSON(w, http.StatusOK, map[string]any{"acc": 1})
	}
}

// WriteJSON writes v as JSON with status.
func WriteJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	if v != nil {
		json.NewEncoder(w).Encode(v)
	}
}
