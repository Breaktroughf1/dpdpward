// Package config reads dpdpward.yaml: the organisation's declared purposes,
// lawful basis, retention, processors and safeguard attestations. Code shows
// where personal data is; only people can say why it is processed.
package config

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"gopkg.in/yaml.v3"
)

// FileName is the default config file name.
const FileName = "dpdpward.yaml"

// Config is dpdpward.yaml.
type Config struct {
	Version      int             `yaml:"version"`
	Organisation Organisation    `yaml:"organisation"`
	Exclude      []string        `yaml:"exclude"`
	Purposes     []Purpose       `yaml:"purposes"`
	Children     Children        `yaml:"children"`
	Safeguards   map[string]Attn `yaml:"safeguards"`
	Ignore       []Ignore        `yaml:"ignore"`
}

// Organisation identifies the Data Fiduciary and its contacts.
type Organisation struct {
	Name             string `yaml:"name"`
	GrievanceContact string `yaml:"grievance_contact"` // person who answers Data Principals' questions
	DPO              string `yaml:"dpo"`               // Significant Data Fiduciaries only
	CertInContact    string `yaml:"cert_in_contact"`   // point of contact for CERT-In
}

// Purpose is one processing purpose, the unit of the ROPA.
type Purpose struct {
	ID             string   `yaml:"id"`
	Description    string   `yaml:"description"`
	Basis          string   `yaml:"basis"`          // consent | legitimate-use
	LegitimateUse  string   `yaml:"legitimate_use"` // the s.7 clause relied on
	DataPrincipals []string `yaml:"data_principals"`
	Stores         []string `yaml:"stores"` // store names or glob patterns
	Retention      string   `yaml:"retention"`
	Processors     []string `yaml:"processors"`
	Transfers      []string `yaml:"transfers_outside_india"` // countries, empty if none
	Children       bool     `yaml:"children"`
}

// Children records the verifiable-consent mechanism (s.9).
type Children struct {
	VerifiableConsent bool   `yaml:"verifiable_consent"`
	Mechanism         string `yaml:"mechanism"`
}

// Attn is an attestation for a safeguard code cannot show.
type Attn struct {
	Evidence []string `yaml:"evidence"` // repo paths or https URLs
	Notes    string   `yaml:"notes"`
}

// Ignore suppresses a classification judged wrong, with a reason.
type Ignore struct {
	Store  string `yaml:"store"`
	Field  string `yaml:"field"`
	Reason string `yaml:"reason"`
}

// Load reads path. A missing file returns (nil, nil): the scan still runs,
// and every store is reported as having no declared purpose.
func Load(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var c Config
	dec := yaml.NewDecoder(strings.NewReader(string(data)))
	dec.KnownFields(true) // a misspelt key must not silently drop a declaration
	if err := dec.Decode(&c); err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	if err := c.validate(); err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	return &c, nil
}

// Safeguard keys, one per DPDP Rules 2025 Rule 6(1) item.
var SafeguardKeys = []string{"encryption", "access_control", "logging", "backups", "log_retention", "processor_contracts", "organisational"}

func (c *Config) validate() error {
	if c.Version != 0 && c.Version != 1 {
		return fmt.Errorf("unsupported version %d", c.Version)
	}
	seen := map[string]bool{}
	for i, p := range c.Purposes {
		if p.ID == "" {
			return fmt.Errorf("purposes[%d]: id is required", i)
		}
		if seen[p.ID] {
			return fmt.Errorf("purpose %q declared twice", p.ID)
		}
		seen[p.ID] = true
		switch p.Basis {
		case "", "consent", "legitimate-use":
		default:
			return fmt.Errorf("purpose %q: basis must be consent or legitimate-use, not %q", p.ID, p.Basis)
		}
		for _, s := range p.Stores {
			if _, err := filepath.Match(s, "x"); err != nil {
				return fmt.Errorf("purpose %q: bad store pattern %q", p.ID, s)
			}
		}
	}
	known := map[string]bool{}
	for _, k := range SafeguardKeys {
		known[k] = true
	}
	for k := range c.Safeguards {
		if !known[k] {
			return fmt.Errorf("unknown safeguard %q (want one of %s)", k, strings.Join(SafeguardKeys, ", "))
		}
	}
	return nil
}

// MatchStore reports whether a store name matches a purpose's patterns
// (case-insensitive glob).
func (p Purpose) MatchStore(name string) bool {
	for _, pat := range p.Stores {
		if ok, _ := filepath.Match(strings.ToLower(pat), strings.ToLower(name)); ok {
			return true
		}
	}
	return false
}
