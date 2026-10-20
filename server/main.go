package main

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"time"

	"github.com/user/banner-fingerprint/internal/engine"
	"github.com/user/banner-fingerprint/internal/models"
)

var eng *engine.Engine

func main() {
	// Support a lightweight health-check mode used by the Docker HEALTHCHECK
	// instruction: make a GET /health request to ourselves and exit 0/1.
	if len(os.Args) > 1 && os.Args[1] == "-health-check" {
		runHealthCheck()
		return
	}

	rulesPath := os.Getenv("RULES_PATH")
	if rulesPath == "" {
		rulesPath = "/app/rules/fingerprints.yaml"
	}

	var err error
	eng, err = engine.LoadFromFile(rulesPath)
	if err != nil {
		log.Fatalf("failed to load rules from %s: %v", rulesPath, err)
	}
	log.Printf("rules loaded from %s", rulesPath)

	mux := http.NewServeMux()
	mux.HandleFunc("/health", handleHealth)
	mux.HandleFunc("/fingerprint", handleFingerprint)

	addr := ":8080"
	srv := &http.Server{
		Addr:         addr,
		Handler:      mux,
		ReadTimeout:  10 * time.Second,
		WriteTimeout: 30 * time.Second,
		IdleTimeout:  60 * time.Second,
	}

	log.Printf("server listening on %s", addr)
	if err := srv.ListenAndServe(); err != nil {
		log.Fatalf("server error: %v", err)
	}
}

// runHealthCheck calls GET /health on the local server and exits appropriately.
func runHealthCheck() {
	client := &http.Client{Timeout: 3 * time.Second}
	resp, err := client.Get("http://localhost:8080/health")
	if err != nil {
		fmt.Fprintf(os.Stderr, "health check failed: %v\n", err)
		os.Exit(1)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		fmt.Fprintf(os.Stderr, "health check returned %d\n", resp.StatusCode)
		os.Exit(1)
	}
	os.Exit(0)
}

// handleHealth returns 200 OK with a simple JSON body.
func handleHealth(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(map[string]string{"status": "ok"})
}

// handleFingerprint accepts POST /fingerprint with a JSON body and returns results.
func handleFingerprint(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req models.FingerprintRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "invalid JSON: "+err.Error(), http.StatusBadRequest)
		return
	}

	results := eng.FingerprintBatch(req.Targets)

	resp := models.FingerprintResponse{Results: results}
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(resp); err != nil {
		log.Printf("encode error: %v", err)
	}
}
