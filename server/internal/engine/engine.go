package engine

import (
	"os"
	"regexp"
	"strings"
	"sync"

	"github.com/user/banner-fingerprint/internal/models"
	"gopkg.in/yaml.v3"
)

// rule mirrors a single entry in fingerprints.yaml.
type rule struct {
	Name           string   `yaml:"name"`
	Protocol       string   `yaml:"protocol"`
	Product        string   `yaml:"product"`
	Patterns       []string `yaml:"patterns"`
	VersionPattern string   `yaml:"version_pattern"`
	OSPattern      string   `yaml:"os_pattern"`
	Confidence     float64  `yaml:"confidence"`

	// compiled regexes (populated at load time)
	compiled        []*regexp.Regexp
	compiledVersion *regexp.Regexp
	compiledOS      *regexp.Regexp
}

type rulesFile struct {
	Rules []rule `yaml:"rules"`
}

// Engine holds the compiled ruleset and fingerprints banners.
type Engine struct {
	rules []rule
}

var loadOnce sync.Once
var globalEngine *Engine
var loadErr error

// LoadFromFile reads and compiles the rule file. Call once at startup.
func LoadFromFile(path string) (*Engine, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	var rf rulesFile
	if err := yaml.Unmarshal(data, &rf); err != nil {
		return nil, err
	}

	e := &Engine{}
	for i := range rf.Rules {
		r := &rf.Rules[i]
		for _, pat := range r.Patterns {
			re, err := regexp.Compile(pat)
			if err != nil {
				// Skip invalid patterns rather than crashing.
				continue
			}
			r.compiled = append(r.compiled, re)
		}
		if r.VersionPattern != "" {
			re, err := regexp.Compile(r.VersionPattern)
			if err == nil {
				r.compiledVersion = re
			}
		}
		if r.OSPattern != "" {
			re, err := regexp.Compile(r.OSPattern)
			if err == nil {
				r.compiledOS = re
			}
		}
		e.rules = append(e.rules, *r)
	}
	return e, nil
}

// Fingerprint identifies a single scan input. It never returns an error;
// unrecognised banners yield protocol="unknown".
func (e *Engine) Fingerprint(input models.ScanInput) models.FingerprintResult {
	result := models.FingerprintResult{
		IP:       input.IP,
		Port:     input.Port,
		Protocol: "unknown",
	}

	// Unescape common escape sequences so we can match binary banners.
	banner := unescape(input.Banner)

	for _, r := range e.rules {
		if matchesAny(r.compiled, banner) {
			result.Protocol = r.Protocol
			result.Product = r.Product
			result.Confidence = r.Confidence

			if r.compiledVersion != nil {
				if m := r.compiledVersion.FindStringSubmatch(banner); len(m) > 1 {
					result.Version = strings.TrimSpace(m[1])
				}
			}
			if r.compiledOS != nil {
				if m := r.compiledOS.FindStringSubmatch(banner); len(m) > 1 {
					result.OSHint = strings.TrimSpace(m[1])
				} else if r.OSPattern != "" && !strings.Contains(r.OSPattern, "(") {
					// Static OS hint (no capture group), e.g. "Windows"
					result.OSHint = r.OSPattern
				}
			} else if r.OSPattern != "" && !strings.Contains(r.OSPattern, "(") {
				result.OSHint = r.OSPattern
			}

			return result
		}
	}

	// Port-based fallback to improve unknown detection.
	result = portFallback(result, input.Port)
	return result
}

// FingerprintBatch processes a slice of inputs concurrently.
func (e *Engine) FingerprintBatch(inputs []models.ScanInput) []models.FingerprintResult {
	results := make([]models.FingerprintResult, len(inputs))
	var wg sync.WaitGroup
	for i, inp := range inputs {
		wg.Add(1)
		go func(idx int, in models.ScanInput) {
			defer wg.Done()
			results[idx] = e.Fingerprint(in)
		}(i, inp)
	}
	wg.Wait()
	return results
}

// matchesAny returns true when at least one compiled regex matches banner.
func matchesAny(res []*regexp.Regexp, banner string) bool {
	for _, re := range res {
		if re.MatchString(banner) {
			return true
		}
	}
	return false
}

// unescape converts Go-style escape sequences in a banner string so that
// binary content like \x00 or \n can be matched by the regex engine.
func unescape(s string) string {
	// strconv.Unquote requires surrounding quotes; do it manually.
	var b strings.Builder
	b.Grow(len(s))
	i := 0
	for i < len(s) {
		if s[i] == '\\' && i+1 < len(s) {
			switch s[i+1] {
			case 'x', 'X':
				if i+3 < len(s) {
					hi := hexVal(s[i+2])
					lo := hexVal(s[i+3])
					if hi >= 0 && lo >= 0 {
						b.WriteByte(byte(hi<<4 | lo))
						i += 4
						continue
					}
				}
			case 'n':
				b.WriteByte('\n')
				i += 2
				continue
			case 'r':
				b.WriteByte('\r')
				i += 2
				continue
			case 't':
				b.WriteByte('\t')
				i += 2
				continue
			case '\\':
				b.WriteByte('\\')
				i += 2
				continue
			}
		}
		b.WriteByte(s[i])
		i++
	}
	return b.String()
}

func hexVal(c byte) int {
	switch {
	case c >= '0' && c <= '9':
		return int(c - '0')
	case c >= 'a' && c <= 'f':
		return int(c-'a') + 10
	case c >= 'A' && c <= 'F':
		return int(c-'A') + 10
	}
	return -1
}

// portFallback assigns a low-confidence protocol guess based on well-known ports
// when the banner could not be matched.
func portFallback(r models.FingerprintResult, port int) models.FingerprintResult {
	type hint struct {
		proto      string
		confidence float64
	}
	known := map[int]hint{
		21:   {"FTP", 0.4},
		22:   {"SSH", 0.4},
		23:   {"Telnet", 0.4},
		25:   {"SMTP", 0.4},
		53:   {"DNS", 0.4},
		80:   {"HTTP", 0.4},
		110:  {"POP3", 0.4},
		143:  {"IMAP", 0.4},
		443:  {"HTTPS", 0.4},
		445:  {"SMB", 0.4},
		3306: {"MySQL", 0.4},
		3389: {"RDP", 0.4},
		5432: {"PostgreSQL", 0.4},
		6379: {"Redis", 0.4},
		8080: {"HTTP", 0.4},
		8443: {"HTTPS", 0.4},
		9200: {"Elasticsearch", 0.4},
		27017: {"MongoDB", 0.4},
	}
	if h, ok := known[port]; ok {
		r.Protocol = h.proto
		r.Confidence = h.confidence
	}
	return r
}
