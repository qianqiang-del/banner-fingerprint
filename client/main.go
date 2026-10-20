package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"text/tabwriter"
	"time"
)

// ScanInput mirrors the server model.
type ScanInput struct {
	IP     string `json:"ip"`
	Port   int    `json:"port"`
	Banner string `json:"banner"`
}

// FingerprintRequest wraps a batch of scan inputs.
type FingerprintRequest struct {
	Targets []ScanInput `json:"targets"`
}

// FingerprintResult is one enriched record.
type FingerprintResult struct {
	IP         string  `json:"ip"`
	Port       int     `json:"port"`
	Protocol   string  `json:"protocol"`
	Product    string  `json:"product"`
	Version    string  `json:"version"`
	OSHint     string  `json:"os_hint"`
	Confidence float64 `json:"confidence"`
}

// FingerprintResponse wraps the batch results.
type FingerprintResponse struct {
	Results []FingerprintResult `json:"results"`
}

func main() {
	if len(os.Args) < 2 {
		log.Fatal("usage: client <input.json> [server-url]")
	}

	inputFile := os.Args[1]
	serverURL := "http://server:8080"
	if len(os.Args) >= 3 {
		serverURL = os.Args[2]
	}

	// Read input file.
	data, err := os.ReadFile(inputFile)
	if err != nil {
		log.Fatalf("cannot read %s: %v", inputFile, err)
	}

	// Accept a bare JSON array or a wrapped {"targets":[...]} object.
	var targets []ScanInput
	if err := json.Unmarshal(data, &targets); err != nil {
		var req FingerprintRequest
		if err2 := json.Unmarshal(data, &req); err2 != nil {
			log.Fatalf("cannot parse input (tried array and wrapped object): %v", err)
		}
		targets = req.Targets
	}

	if len(targets) == 0 {
		log.Fatal("input contains no targets")
	}

	// Build and POST request.
	reqBody, _ := json.Marshal(FingerprintRequest{Targets: targets})

	httpClient := &http.Client{Timeout: 30 * time.Second}
	resp, err := httpClient.Post(serverURL+"/fingerprint", "application/json", bytes.NewReader(reqBody))
	if err != nil {
		log.Fatalf("POST %s/fingerprint: %v", serverURL, err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		log.Fatalf("reading response: %v", err)
	}
	if resp.StatusCode != http.StatusOK {
		log.Fatalf("server returned %d: %s", resp.StatusCode, body)
	}

	var result FingerprintResponse
	if err := json.Unmarshal(body, &result); err != nil {
		log.Fatalf("cannot parse response: %v\nraw: %s", err, body)
	}

	printTable(result.Results)

	pretty, _ := json.MarshalIndent(result.Results, "", "  ")
	fmt.Printf("\n--- JSON output ---\n%s\n", pretty)
}

func printTable(results []FingerprintResult) {
	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintln(w, "IP\tPORT\tPROTOCOL\tPRODUCT\tVERSION\tOS_HINT\tCONF")
	fmt.Fprintln(w, "--\t----\t--------\t-------\t-------\t-------\t----")
	for _, r := range results {
		fmt.Fprintf(w, "%s\t%d\t%s\t%s\t%s\t%s\t%.2f\n",
			r.IP, r.Port, r.Protocol, r.Product, r.Version, r.OSHint, r.Confidence)
	}
	_ = w.Flush()
}
