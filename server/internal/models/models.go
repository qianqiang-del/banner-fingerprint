package models

// ScanInput is one raw record from the scanner.
type ScanInput struct {
	IP     string `json:"ip"`
	Port   int    `json:"port"`
	Banner string `json:"banner"`
}

// FingerprintResult is the enriched record returned to callers.
type FingerprintResult struct {
	IP         string  `json:"ip"`
	Port       int     `json:"port"`
	Protocol   string  `json:"protocol"`
	Product    string  `json:"product"`
	Version    string  `json:"version"`
	OSHint     string  `json:"os_hint"`
	Confidence float64 `json:"confidence"`
}

// FingerprintRequest wraps a batch of scan inputs.
type FingerprintRequest struct {
	Targets []ScanInput `json:"targets"`
}

// FingerprintResponse wraps the batch results.
type FingerprintResponse struct {
	Results []FingerprintResult `json:"results"`
}
