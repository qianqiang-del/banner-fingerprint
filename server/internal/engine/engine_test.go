package engine_test

import (
	"testing"

	"github.com/user/banner-fingerprint/internal/engine"
	"github.com/user/banner-fingerprint/internal/models"
)

// loadEngine is a helper that loads the real rule file once.
func loadEngine(t *testing.T) *engine.Engine {
	t.Helper()
	e, err := engine.LoadFromFile("../../rules/fingerprints.yaml")
	if err != nil {
		t.Fatalf("LoadFromFile: %v", err)
	}
	return e
}

// tc is a single test case.
type tc struct {
	name             string
	input            models.ScanInput
	wantProtocol     string
	wantProduct      string
	wantVersionStart string // version must start with this string (empty = don't check)
	wantOSContains   string // os_hint must contain this string (empty = don't check)
	wantConfMin      float64
}

func TestFingerprint(t *testing.T) {
	e := loadEngine(t)

	cases := []tc{
		// ── SSH ──────────────────────────────────────────────────────────────
		{
			name:             "OpenSSH Ubuntu",
			input:            models.ScanInput{IP: "1.2.3.4", Port: 22, Banner: "SSH-2.0-OpenSSH_8.9p1 Ubuntu-3"},
			wantProtocol:     "SSH",
			wantProduct:      "OpenSSH",
			wantVersionStart: "8.9p1",
			wantOSContains:   "Ubuntu",
			wantConfMin:      0.9,
		},
		{
			name:             "OpenSSH Debian",
			input:            models.ScanInput{IP: "1.2.3.11", Port: 22, Banner: "SSH-2.0-OpenSSH_9.3 Debian-1"},
			wantProtocol:     "SSH",
			wantProduct:      "OpenSSH",
			wantVersionStart: "9.3",
			wantOSContains:   "Debian",
			wantConfMin:      0.9,
		},
		{
			name:             "OpenSSH old generic",
			input:            models.ScanInput{IP: "1.2.3.18", Port: 22, Banner: "SSH-1.99-OpenSSH_4.3"},
			wantProtocol:     "SSH",
			wantProduct:      "OpenSSH",
			wantVersionStart: "4.3",
			wantConfMin:      0.85,
		},
		{
			name:         "Dropbear SSH",
			input:        models.ScanInput{IP: "2.0.0.14", Port: 22, Banner: "SSH-2.0-dropbear_2022.83"},
			wantProtocol: "SSH",
			wantConfMin:  0.5,
		},

		// ── HTTP / nginx ─────────────────────────────────────────────────────
		{
			name:             "nginx exact",
			input:            models.ScanInput{IP: "1.2.3.5", Port: 80, Banner: "HTTP/1.1 200 OK\r\nServer: nginx/1.24.0\r\nContent-Type: text/html"},
			wantProtocol:     "HTTP",
			wantProduct:      "nginx",
			wantVersionStart: "1.24.0",
			wantConfMin:      0.85,
		},
		{
			name:             "nginx Ubuntu",
			input:            models.ScanInput{IP: "1.2.3.12", Port: 80, Banner: "HTTP/1.1 200 OK\r\nServer: nginx/1.18.0 (Ubuntu)"},
			wantProtocol:     "HTTP",
			wantProduct:      "nginx",
			wantVersionStart: "1.18.0",
			wantOSContains:   "Ubuntu",
			wantConfMin:      0.9,
		},
		{
			name:             "nginx 301 redirect",
			input:            models.ScanInput{IP: "2.0.0.17", Port: 80, Banner: "HTTP/1.1 301 Moved Permanently\r\nLocation: https://example.com/\r\nServer: nginx/1.20.1"},
			wantProtocol:     "HTTP",
			wantProduct:      "nginx",
			wantVersionStart: "1.20.1",
			wantConfMin:      0.85,
		},

		// ── HTTP / Apache ────────────────────────────────────────────────────
		{
			name:             "Apache bare",
			input:            models.ScanInput{IP: "1.2.3.6", Port: 443, Banner: "HTTP/1.1 200 OK\r\nServer: Apache/2.4.57"},
			wantProtocol:     "HTTP",
			wantProduct:      "Apache",
			wantVersionStart: "2.4.57",
			wantConfMin:      0.85,
		},
		{
			name:             "Apache Ubuntu",
			input:            models.ScanInput{IP: "1.2.3.13", Port: 443, Banner: "HTTP/1.1 200 OK\r\nServer: Apache/2.4.41 (Ubuntu)"},
			wantProtocol:     "HTTP",
			wantProduct:      "Apache",
			wantVersionStart: "2.4.41",
			wantOSContains:   "Ubuntu",
			wantConfMin:      0.9,
		},
		{
			name:             "Apache Debian",
			input:            models.ScanInput{IP: "2.0.0.18", Port: 443, Banner: "HTTP/1.1 200 OK\r\nServer: Apache/2.4.54 (Debian)"},
			wantProtocol:     "HTTP",
			wantProduct:      "Apache",
			wantVersionStart: "2.4.54",
			wantOSContains:   "Debian",
			wantConfMin:      0.9,
		},

		// ── HTTP / Jetty ─────────────────────────────────────────────────────
		{
			name:             "Jetty",
			input:            models.ScanInput{IP: "1.2.3.10", Port: 8080, Banner: "HTTP/1.1 404 Not Found\r\nServer: Jetty/9.4.51"},
			wantProtocol:     "HTTP",
			wantProduct:      "Jetty",
			wantVersionStart: "9.4.51",
			wantConfMin:      0.8,
		},

		// ── HTTP / IIS ───────────────────────────────────────────────────────
		{
			name:             "Microsoft IIS",
			input:            models.ScanInput{IP: "1.2.3.20", Port: 8888, Banner: "HTTP/1.1 200 OK\r\nServer: Microsoft-IIS/10.0"},
			wantProtocol:     "HTTP",
			wantProduct:      "Microsoft-IIS",
			wantVersionStart: "10.0",
			wantConfMin:      0.85,
		},

		// ── HTTP / lighttpd ──────────────────────────────────────────────────
		{
			name:             "lighttpd",
			input:            models.ScanInput{IP: "2.0.0.11", Port: 80, Banner: "HTTP/1.1 200 OK\r\nServer: lighttpd/1.4.71"},
			wantProtocol:     "HTTP",
			wantProduct:      "lighttpd",
			wantVersionStart: "1.4.71",
			wantConfMin:      0.85,
		},

		// ── HTTP / Tomcat ────────────────────────────────────────────────────
		{
			name:         "Apache Tomcat (Coyote)",
			input:        models.ScanInput{IP: "2.0.0.12", Port: 8080, Banner: "HTTP/1.1 200 OK\r\nServer: Apache-Coyote/1.1\r\nContent-Type: text/html"},
			wantProtocol: "HTTP",
			wantProduct:  "Apache Tomcat",
			wantConfMin:  0.8,
		},

		// ── HTTP / Caddy ─────────────────────────────────────────────────────
		{
			name:         "Caddy",
			input:        models.ScanInput{IP: "2.0.0.13", Port: 443, Banner: "HTTP/1.1 200 OK\r\nServer: Caddy\r\nContent-Type: text/html"},
			wantProtocol: "HTTP",
			wantProduct:  "Caddy",
			wantConfMin:  0.8,
		},

		// ── HTTP / Elasticsearch ─────────────────────────────────────────────
		{
			name:             "Elasticsearch",
			input:            models.ScanInput{IP: "2.0.0.6", Port: 9200, Banner: "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\r\n{\"name\":\"node1\",\"tagline\":\"You Know, for Search\",\"version\":{\"number\":\"8.6.0\"}}"},
			wantProtocol:     "HTTP",
			wantProduct:      "Elasticsearch",
			wantVersionStart: "8.6.0",
			wantConfMin:      0.9,
		},

		// ── MySQL ────────────────────────────────────────────────────────────
		{
			name:             "MySQL 8",
			input:            models.ScanInput{IP: "1.2.3.7", Port: 3306, Banner: "J\x00\x00\x00\n8.0.32\x00"},
			wantProtocol:     "MySQL",
			wantProduct:      "MySQL",
			wantVersionStart: "8.0.32",
			wantConfMin:      0.85,
		},
		{
			name:             "MySQL 5.7",
			input:            models.ScanInput{IP: "1.2.3.14", Port: 3306, Banner: "J\x00\x00\x00\n5.7.42\x00"},
			wantProtocol:     "MySQL",
			wantProduct:      "MySQL",
			wantVersionStart: "5.7.42",
			wantConfMin:      0.85,
		},
		{
			name:             "MariaDB banner",
			input:            models.ScanInput{IP: "2.0.0.19", Port: 3306, Banner: "J\u0000\u0000\u0000\n5.5.68-MariaDB\u0000"},
			wantProtocol:     "MySQL",
			wantProduct:      "MariaDB",
			wantVersionStart: "5.5.68",
			wantConfMin:      0.85,
		},

		// ── Redis ────────────────────────────────────────────────────────────
		{
			name:         "Redis PONG",
			input:        models.ScanInput{IP: "1.2.3.15", Port: 6379, Banner: "+PONG"},
			wantProtocol: "Redis",
			wantProduct:  "Redis",
			wantConfMin:  0.85,
		},
		{
			name:         "Redis ERR",
			input:        models.ScanInput{IP: "1.2.3.8", Port: 6379, Banner: "-ERR wrong number of arguments for 'get' command"},
			wantProtocol: "Redis",
			wantProduct:  "Redis",
			wantConfMin:  0.65,
		},
		{
			name:         "Redis NOAUTH",
			input:        models.ScanInput{IP: "1.2.3.21", Port: 6379, Banner: "-NOAUTH Authentication required."},
			wantProtocol: "Redis",
			wantProduct:  "Redis",
			wantConfMin:  0.85,
		},
		{
			name:         "Redis WRONGPASS",
			input:        models.ScanInput{IP: "2.0.0.15", Port: 6379, Banner: "-WRONGPASS invalid username-password pair"},
			wantProtocol: "Redis",
			wantProduct:  "Redis",
			wantConfMin:  0.85,
		},

		// ── FTP ──────────────────────────────────────────────────────────────
		{
			name:             "ProFTPD",
			input:            models.ScanInput{IP: "1.2.3.9", Port: 21, Banner: "220 ProFTPD 1.3.7 Server (ProFTPD)"},
			wantProtocol:     "FTP",
			wantProduct:      "ProFTPD",
			wantVersionStart: "1.3.7",
			wantConfMin:      0.85,
		},
		{
			name:             "vsFTPd",
			input:            models.ScanInput{IP: "1.2.3.16", Port: 21, Banner: "220 (vsFTPd 3.0.5)"},
			wantProtocol:     "FTP",
			wantProduct:      "vsFTPd",
			wantVersionStart: "3.0.5",
			wantConfMin:      0.85,
		},
		{
			name:         "Pure-FTPd",
			input:        models.ScanInput{IP: "1.2.3.22", Port: 21, Banner: "220 Welcome to Pure-FTPd"},
			wantProtocol: "FTP",
			wantProduct:  "Pure-FTPd",
			wantConfMin:  0.8,
		},
		{
			name:         "FTP generic",
			input:        models.ScanInput{IP: "2.0.0.16", Port: 21, Banner: "220 FTP server ready.\r\n"},
			wantProtocol: "FTP",
			wantConfMin:  0.5,
		},

		// ── SMTP ─────────────────────────────────────────────────────────────
		{
			name:         "Postfix",
			input:        models.ScanInput{IP: "2.0.0.1", Port: 25, Banner: "220 mail.example.com ESMTP Postfix (Ubuntu)"},
			wantProtocol: "SMTP",
			wantProduct:  "Postfix",
			wantConfMin:  0.85,
		},
		{
			name:             "Exim",
			input:            models.ScanInput{IP: "2.0.0.2", Port: 25, Banner: "220 smtp.example.org ESMTP Exim 4.96"},
			wantProtocol:     "SMTP",
			wantProduct:      "Exim",
			wantVersionStart: "4.96",
			wantConfMin:      0.85,
		},
		{
			name:         "Sendmail",
			input:        models.ScanInput{IP: "2.0.0.3", Port: 25, Banner: "220 mx.example.net Sendmail 8.15.2/8.15.2"},
			wantProtocol: "SMTP",
			wantProduct:  "Sendmail",
			wantConfMin:  0.8,
		},

		// ── VNC ──────────────────────────────────────────────────────────────
		{
			name:             "VNC",
			input:            models.ScanInput{IP: "2.0.0.8", Port: 5900, Banner: "RFB 003.008\n"},
			wantProtocol:     "VNC",
			wantVersionStart: "003.008",
			wantConfMin:      0.85,
		},

		// ── Telnet ───────────────────────────────────────────────────────────
		{
			name:         "Telnet IAC",
			input:        models.ScanInput{IP: "2.0.0.9", Port: 23, Banner: "\xff\xfb\x01\xff\xfb\x03\xff\xfd\x18\xff\xfd\x1f"},
			wantProtocol: "Telnet",
			wantConfMin:  0.65,
		},

		// ── RDP ──────────────────────────────────────────────────────────────
		{
			name:         "RDP handshake",
			input:        models.ScanInput{IP: "2.0.0.10", Port: 3389, Banner: "\x03\x00\x00\x0b\x06\xd0\x00\x00\x01\x00\x00"},
			wantProtocol: "RDP",
			wantConfMin:  0.7,
		},

		// ── Memcached ────────────────────────────────────────────────────────
		{
			name:             "Memcached",
			input:            models.ScanInput{IP: "2.0.0.7", Port: 11211, Banner: "VERSION 1.6.18\r\n"},
			wantProtocol:     "Memcached",
			wantVersionStart: "1.6.18",
			wantConfMin:      0.75,
		},

		// ── TLS handshake ────────────────────────────────────────────────────
		{
			name:         "TLS ClientHello",
			input:        models.ScanInput{IP: "1.2.3.19", Port: 9999, Banner: "\x16\x03\x01\x00\xa5\x01\x00\x00\xa1"},
			wantProtocol: "TLS",
			wantConfMin:  0.75,
		},

		// ── MongoDB ──────────────────────────────────────────────────────────
		{
			name:             "MongoDB",
			input:            models.ScanInput{IP: "2.0.0.5", Port: 27017, Banner: `{"ismaster":true,"maxBsonObjectSize":16777216,"version":"6.0.4","ok":1}`},
			wantProtocol:     "MongoDB",
			wantProduct:      "MongoDB",
			wantVersionStart: "6.0.4",
			wantConfMin:      0.8,
		},

		// ── Unknown / fallback ───────────────────────────────────────────────
		{
			name:         "Truly unknown banner",
			input:        models.ScanInput{IP: "1.2.3.23", Port: 12345, Banner: "QUIT\r\n"},
			wantProtocol: "unknown",
			wantConfMin:  0,
		},
		{
			name:         "Empty banner unknown port",
			input:        models.ScanInput{IP: "2.0.0.20", Port: 8080, Banner: ""},
			wantProtocol: "HTTP", // port-based fallback
			wantConfMin:  0.3,
		},
		{
			name:         "Empty banner port 0",
			input:        models.ScanInput{IP: "2.0.0.21", Port: 0, Banner: ""},
			wantProtocol: "unknown",
		},
	}

	for _, c := range cases {
		c := c
		t.Run(c.name, func(t *testing.T) {
			t.Parallel()
			result := e.Fingerprint(c.input)

			if result.Protocol != c.wantProtocol {
				t.Errorf("protocol: got %q, want %q", result.Protocol, c.wantProtocol)
			}
			if c.wantProduct != "" && result.Product != c.wantProduct {
				t.Errorf("product: got %q, want %q", result.Product, c.wantProduct)
			}
			if c.wantVersionStart != "" {
				if len(result.Version) < len(c.wantVersionStart) || result.Version[:len(c.wantVersionStart)] != c.wantVersionStart {
					t.Errorf("version: got %q, want prefix %q", result.Version, c.wantVersionStart)
				}
			}
			if c.wantOSContains != "" {
				if !contains(result.OSHint, c.wantOSContains) {
					t.Errorf("os_hint: got %q, want to contain %q", result.OSHint, c.wantOSContains)
				}
			}
			if result.Confidence < c.wantConfMin {
				t.Errorf("confidence: got %.2f, want >= %.2f", result.Confidence, c.wantConfMin)
			}
		})
	}
}

// TestBatchNeverPanics checks that FingerprintBatch never panics or returns
// fewer results than inputs, even with pathological banners.
func TestBatchNeverPanics(t *testing.T) {
	e := loadEngine(t)
	inputs := []models.ScanInput{
		{IP: "0.0.0.0", Port: 0, Banner: ""},
		{IP: "0.0.0.1", Port: 65535, Banner: string([]byte{0x00, 0x01, 0x02, 0x03, 0xff, 0xfe})},
		{IP: "0.0.0.2", Port: 80, Banner: "QUIT\r\n"},
		{IP: "0.0.0.3", Port: 22, Banner: "SSH-2.0-OpenSSH_9.3"},
		{IP: "0.0.0.4", Port: 3306, Banner: "J\x00\x00\x00\n8.0.32\x00"},
		{IP: "0.0.0.5", Port: 6379, Banner: "+PONG"},
	}
	results := e.FingerprintBatch(inputs)
	if len(results) != len(inputs) {
		t.Fatalf("batch returned %d results for %d inputs", len(results), len(inputs))
	}
	for i, r := range results {
		if r.Protocol == "" {
			t.Errorf("result[%d] has empty protocol (must be at least 'unknown')", i)
		}
	}
}

// TestLoadInvalidPath ensures LoadFromFile returns a useful error, not a panic.
func TestLoadInvalidPath(t *testing.T) {
	_, err := engine.LoadFromFile("/nonexistent/path/to/rules.yaml")
	if err == nil {
		t.Fatal("expected error for nonexistent path, got nil")
	}
}

func contains(s, sub string) bool {
	return len(sub) == 0 || (len(s) >= len(sub) && func() bool {
		for i := 0; i <= len(s)-len(sub); i++ {
			if s[i:i+len(sub)] == sub {
				return true
			}
		}
		return false
	}())
}
