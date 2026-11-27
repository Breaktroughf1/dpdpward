// Package analysis turns extracted stores, classified elements, identifier
// values, Terraform checks and dpdpward.yaml into findings, a Record of
// Processing Activities and a Rule 6 safeguards-evidence record.
//
// Nothing here is legal advice. Rule references are to the Digital Personal
// Data Protection Act, 2023 and the DPDP Rules, 2025, as summarised in
// docs/legal-basis.md; verify against the official Gazette text.
package analysis

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/Breaktroughf1/dpdpward/internal/config"
	"github.com/Breaktroughf1/dpdpward/internal/iac"
	"github.com/Breaktroughf1/dpdpward/internal/model"
)

// Severity of a finding.
type Severity int

// Severities.
const (
	Info Severity = iota
	Low
	Medium
	High
	Critical
)

var sevNames = []string{"info", "low", "medium", "high", "critical"}

func (s Severity) String() string { return sevNames[s] }

// ParseSeverity parses a severity name.
func ParseSeverity(s string) (Severity, error) {
	for i, n := range sevNames {
		if strings.EqualFold(n, s) {
			return Severity(i), nil
		}
	}
	return 0, fmt.Errorf("unknown severity %q (want one of %s)", s, strings.Join(sevNames, ", "))
}

// Finding is a rule result.
type Finding struct {
	RuleID      string   `json:"rule_id"`
	Severity    Severity `json:"-"`
	SeverityStr string   `json:"severity"`
	Message     string   `json:"message"`
	File        string   `json:"file,omitempty"`
	Line        int      `json:"line,omitempty"`
	Key         string   `json:"-"`
	Fingerprint string   `json:"fingerprint"`
}

// Safeguard is the evidence state of one Rule 6(1) item.
type Safeguard struct {
	Key      string      `json:"key"`
	Clause   string      `json:"clause"`
	Title    string      `json:"title"`
	Status   string      `json:"status"` // pass | partial | fail | unknown
	Evidence []string    `json:"evidence,omitempty"`
	Checks   []iac.Check `json:"iac_checks,omitempty"`
	Notes    string      `json:"notes,omitempty"`
}

// PurposeRecord is one ROPA row.
type PurposeRecord struct {
	ID             string   `json:"id"`
	Description    string   `json:"description"`
	Basis          string   `json:"basis"`
	LegitimateUse  string   `json:"legitimate_use,omitempty"`
	DataPrincipals []string `json:"data_principals,omitempty"`
	Categories     []string `json:"data_categories"`
	Stores         []string `json:"stores"`
	Retention      string   `json:"retention"`
	Processors     []string `json:"processors,omitempty"`
	Transfers      []string `json:"transfers_outside_india,omitempty"`
	Children       bool     `json:"children"`
}

// Result is the full analysis.
type Result struct {
	Organisation string           `json:"organisation,omitempty"`
	ConfigFound  bool             `json:"config_found"`
	Stores       []model.Store    `json:"stores"`
	Elements     []model.Element  `json:"personal_data"`
	Values       []model.ValueHit `json:"identifier_values"`
	Findings     []Finding        `json:"findings"`
	Safeguards   []Safeguard      `json:"safeguards"`
	ROPA         []PurposeRecord  `json:"ropa"`
	Unmapped     []string         `json:"stores_without_purpose"`
	Gaps         []string         `json:"gaps,omitempty"`
}

// Input collects what was extracted from the tree.
type Input struct {
	Root     string
	Config   *config.Config
	Stores   []model.Store
	Elements []model.Element
	Values   []model.ValueHit
	IaC      []iac.Check
	Skipped  []string
}

// SafeguardTitles maps Rule 6(1) items to their clauses and titles.
var SafeguardTitles = []struct{ Key, Clause, Title string }{
	{"encryption", "6(1)(a)", "Encryption, obfuscation, masking or virtual tokens"},
	{"access_control", "6(1)(b)", "Access control over computer resources"},
	{"logging", "6(1)(c)", "Visibility of access through logs, monitoring and review"},
	{"backups", "6(1)(d)", "Continued processing after compromise, including backups"},
	{"log_retention", "6(1)(e)", "Logs and personal data retained for one year"},
	{"processor_contracts", "6(1)(f)", "Safeguard obligations in contracts with Data Processors"},
	{"organisational", "6(1)(g)", "Technical and organisational measures to make safeguards effective"},
}

// Analyze evaluates every rule.
func Analyze(in Input) Result {
	a := &analyzer{in: in}
	a.res.Stores = in.Stores
	a.res.Values = in.Values
	a.res.Gaps = in.Skipped
	if in.Config != nil {
		a.res.ConfigFound = true
		a.res.Organisation = in.Config.Organisation.Name
	}
	a.res.Elements = a.applyIgnores(in.Elements)
	a.purposes()
	a.identifiers()
	a.children()
	a.values()
	a.safeguards()
	a.contacts()
	a.consentRecords()
	a.significant()
	sort.SliceStable(a.res.Findings, func(i, j int) bool {
		fi, fj := a.res.Findings[i], a.res.Findings[j]
		if fi.Severity != fj.Severity {
			return fi.Severity > fj.Severity
		}
		if fi.RuleID != fj.RuleID {
			return fi.RuleID < fj.RuleID
		}
		return fi.Key < fj.Key
	})
	return a.res
}

type analyzer struct {
	in  Input
	res Result
}

func (a *analyzer) add(rule string, sev Severity, file string, line int, key, msg string) {
	h := sha256.Sum256([]byte(rule + "|" + key))
	a.res.Findings = append(a.res.Findings, Finding{RuleID: rule, Severity: sev, SeverityStr: sev.String(),
		Message: msg, File: file, Line: line, Key: key, Fingerprint: hex.EncodeToString(h[:12])})
}

func (a *analyzer) applyIgnores(els []model.Element) []model.Element {
	if a.in.Config == nil || len(a.in.Config.Ignore) == 0 {
		return els
	}
	var out []model.Element
	for _, e := range els {
		skip := false
		for _, ig := range a.in.Config.Ignore {
			if strings.EqualFold(ig.Store, e.Store) && strings.EqualFold(ig.Field, e.Field) {
				if ig.Reason == "" {
					a.add("DP013", Low, e.File, e.Line, "ignore|"+e.Store+"."+e.Field,
						fmt.Sprintf("Ignore entry for %s.%s has no reason; it is not applied. Record why the field is not personal data.", e.Store, e.Field))
					break
				}
				skip = true
			}
		}
		if !skip {
			out = append(out, e)
		}
	}
	return out
}

// byStore groups elements by store name.
func (a *analyzer) byStore() (map[string][]model.Element, []string) {
	m := map[string][]model.Element{}
	for _, e := range a.res.Elements {
		m[e.Store] = append(m[e.Store], e)
	}
	names := make([]string, 0, len(m))
	for n := range m {
		names = append(names, n)
	}
	sort.Strings(names)
	return m, names
}

func (a *analyzer) purposes() {
	byStore, names := a.byStore()
	cfg := a.in.Config
	if cfg == nil {
		a.res.Unmapped = names
		for _, n := range names {
			e := byStore[n][0]
			a.add("DP001", High, e.File, e.Line, "unmapped|"+n,
				fmt.Sprintf("%s holds personal data (%s) but no purpose is declared for it. Create dpdpward.yaml (dpdpward init) and map each store to a purpose, lawful basis and retention period.", n, labels(byStore[n])))
		}
		return
	}
	mapped := map[string]bool{}
	for _, p := range cfg.Purposes {
		rec := PurposeRecord{ID: p.ID, Description: p.Description, Basis: p.Basis, LegitimateUse: p.LegitimateUse,
			DataPrincipals: p.DataPrincipals, Retention: p.Retention, Processors: p.Processors, Transfers: p.Transfers, Children: p.Children}
		cats := map[string]bool{}
		matched := false
		for _, s := range a.in.Stores {
			if !p.MatchStore(s.Name) {
				continue
			}
			matched = true
			rec.Stores = appendUnique(rec.Stores, s.Name)
			for _, e := range byStore[s.Name] {
				cats[e.Label] = true
			}
			mapped[s.Name] = true
		}
		for c := range cats {
			rec.Categories = append(rec.Categories, c)
		}
		sort.Strings(rec.Categories)
		a.res.ROPA = append(a.res.ROPA, rec)
		if !matched && len(p.Stores) > 0 {
			a.add("DP012", Low, config.FileName, 0, "nomatch|"+p.ID,
				fmt.Sprintf("Purpose %q lists stores %s, but none were found in the scanned code. The record may be stale.", p.ID, strings.Join(p.Stores, ", ")))
		}
		switch {
		case p.Basis == "":
			a.add("DP006", Medium, config.FileName, 0, "basis|"+p.ID,
				fmt.Sprintf("Purpose %q has no lawful basis. Personal data may be processed only with consent or for a legitimate use under section 7.", p.ID))
		case p.Basis == "legitimate-use" && strings.TrimSpace(p.LegitimateUse) == "":
			a.add("DP006", Medium, config.FileName, 0, "basis|"+p.ID,
				fmt.Sprintf("Purpose %q relies on legitimate use without naming the section 7 clause.", p.ID))
		}
		if strings.TrimSpace(p.Retention) == "" {
			a.add("DP005", Medium, config.FileName, 0, "retention|"+p.ID,
				fmt.Sprintf("Purpose %q has no retention period. Personal data must be erased once the purpose is served (section 8(7)); record when that is.", p.ID))
		}
		if len(p.Transfers) > 0 {
			a.add("DP014", Info, config.FileName, 0, "transfer|"+p.ID,
				fmt.Sprintf("Purpose %q transfers personal data outside India (%s). Check each country against any restriction notified under section 16.", p.ID, strings.Join(p.Transfers, ", ")))
		}
	}
	for _, n := range names {
		if mapped[n] {
			continue
		}
		a.res.Unmapped = append(a.res.Unmapped, n)
		e := byStore[n][0]
		a.add("DP001", High, e.File, e.Line, "unmapped|"+n,
			fmt.Sprintf("%s holds personal data (%s) but no purpose in dpdpward.yaml covers it. Map it to a purpose with a lawful basis and retention period, or remove the data.", n, labels(byStore[n])))
	}
}

func (a *analyzer) identifiers() {
	for _, e := range a.res.Elements {
		k := e.Store + "." + e.Field
		switch e.Category {
		case "government-id.aadhaar":
			a.add("DP002", High, e.File, e.Line, "aadhaar|"+k,
				fmt.Sprintf("%s appears to store Aadhaar numbers. UIDAI allows only entities permitted to collect Aadhaar to store it, encrypted, in a separate Aadhaar Data Vault; most systems should keep a reference token or the last four digits instead. Confirm your entitlement and storage.", k))
		case "financial.card-security-code":
			a.add("DP003", Critical, e.File, e.Line, "cvv|"+k,
				fmt.Sprintf("%s appears to store a card CVV or PIN. These must never be stored after authorisation (PCI DSS; RBI card data rules). Remove the field.", k))
		case "biometric", "health", "health.abha", "sensitive.demographic":
			a.add("DP011", Low, e.File, e.Line, "sensitive|"+k,
				fmt.Sprintf("%s holds %s. Collect it only if the purpose requires it, restrict access, and weigh it in any Data Protection Impact Assessment.", k, strings.ToLower(e.Label)))
		}
	}
}

func (a *analyzer) children() {
	var hits []model.Element
	for _, e := range a.res.Elements {
		if e.Children {
			hits = append(hits, e)
		}
	}
	if len(hits) == 0 {
		return
	}
	if a.in.Config != nil && a.in.Config.Children.VerifiableConsent && strings.TrimSpace(a.in.Config.Children.Mechanism) != "" {
		return
	}
	var where []string
	for _, h := range hits {
		where = append(where, h.Store+"."+h.Field)
	}
	a.add("DP004", Medium, hits[0].File, hits[0].Line, "children",
		fmt.Sprintf("Fields suggest ages or guardians are recorded (%s). If any Data Principal may be under 18, section 9 requires verifiable parental consent; record the mechanism under children: in dpdpward.yaml.", strings.Join(where, ", ")))
}

func (a *analyzer) values() {
	for _, v := range a.res.Values {
		sev, what := High, ""
		switch v.Kind {
		case "aadhaar":
			what = "an Aadhaar number (valid check digit)"
		case "pan":
			what = "a PAN"
		case "gstin":
			sev, what = Medium, "a GSTIN (valid check character; for sole proprietors it contains the owner's PAN)"
		case "upi":
			sev, what = Medium, "a UPI ID"
		}
		a.add("DP007", sev, v.File, v.Line, fmt.Sprintf("value|%s:%d|%s|%s", v.File, v.Line, v.Kind, v.Redacted),
			fmt.Sprintf("%s:%d contains what looks like %s (%s). Real identifiers in source, fixtures or logs are personal data held without a purpose; replace them with synthetic values and purge them from history.", v.File, v.Line, what, v.Redacted))
	}
}

func (a *analyzer) safeguards() {
	byKey := map[string][]iac.Check{}
	for _, c := range a.in.IaC {
		byKey[c.Safeguard] = append(byKey[c.Safeguard], c)
	}
	for _, t := range SafeguardTitles {
		sg := Safeguard{Key: t.Key, Clause: t.Clause, Title: t.Title, Checks: byKey[t.Key], Status: "unknown"}
		var attn config.Attn
		hasAttn := false
		if a.in.Config != nil {
			attn, hasAttn = a.in.Config.Safeguards[t.Key]
		}
		evidenceOK := false
		if hasAttn {
			sg.Notes = attn.Notes
			for _, ev := range attn.Evidence {
				if strings.HasPrefix(ev, "https://") {
					sg.Evidence = append(sg.Evidence, ev)
					evidenceOK = true
					continue
				}
				if _, err := os.Stat(filepath.Join(a.in.Root, ev)); err == nil {
					sg.Evidence = append(sg.Evidence, ev)
					evidenceOK = true
				} else {
					a.add("DP010", Medium, config.FileName, 0, "evidence|"+t.Key+"|"+ev,
						fmt.Sprintf("Safeguard %s (Rule %s) cites evidence %q, which does not exist in the repository.", t.Key, t.Clause, ev))
				}
			}
		}
		failed := false
		for _, c := range sg.Checks {
			if c.Status == "fail" {
				failed = true
				sev := High
				if t.Key == "log_retention" || t.Key == "backups" {
					sev = Medium
				}
				a.add("DP008", sev, c.File, c.Line, "iac|"+c.Resource+"|"+t.Key+"|"+c.Detail,
					fmt.Sprintf("%s: %s (Rule %s, %s).", c.Resource, c.Detail, t.Clause, strings.ToLower(t.Title)))
			}
		}
		iacPass, iacUnknown := false, false
		for _, c := range sg.Checks {
			switch c.Status {
			case "pass":
				iacPass = true
			case "unknown":
				iacUnknown = true
			}
		}
		// Fail safe: a safeguard passes only with attested evidence, or when
		// every Terraform check for it passes; one undecided check is enough
		// to keep it unknown.
		switch {
		case failed:
			sg.Status = "fail"
		case evidenceOK:
			sg.Status = "pass"
		case iacPass && !iacUnknown:
			// Infrastructure settings are partial evidence: Rule 6 safeguards
			// are organisation-wide processes, not just configuration.
			sg.Status = "partial"
			a.add("DP009", Low, "", 0, "partial|"+t.Key,
				fmt.Sprintf("Rule %s (%s) is evidenced only by infrastructure settings. Attest the wider process with evidence under safeguards.%s in dpdpward.yaml.", t.Clause, strings.ToLower(t.Title), t.Key))
		case iacUnknown:
			a.add("DP009", Medium, "", 0, "unknown|"+t.Key,
				fmt.Sprintf("Rule %s (%s) could not be confirmed: some Terraform settings are unset or computed. Review them, or add an attestation with evidence under safeguards.%s in dpdpward.yaml.", t.Clause, strings.ToLower(t.Title), t.Key))
		default:
			a.add("DP009", Medium, "", 0, "unknown|"+t.Key,
				fmt.Sprintf("No evidence for Rule %s (%s). Nothing in the scanned code shows it; add an attestation with evidence under safeguards.%s in dpdpward.yaml.", t.Clause, strings.ToLower(t.Title), t.Key))
		}
		a.res.Safeguards = append(a.res.Safeguards, sg)
	}
}

func (a *analyzer) contacts() {
	if a.in.Config == nil {
		return
	}
	o := a.in.Config.Organisation
	if strings.TrimSpace(o.GrievanceContact) == "" {
		a.add("DP015", Low, config.FileName, 0, "contact|grievance",
			"No grievance contact is recorded. Notices must give Data Principals a way to exercise their rights and raise grievances.")
	}
	if strings.TrimSpace(o.CertInContact) == "" {
		a.add("DP015", Low, config.FileName, 0, "contact|cert-in",
			"No CERT-In point of contact is recorded. Cyber incidents must be reported to CERT-In within 6 hours of being noticed.")
	}
}

var consentStore = regexp.MustCompile(`(?i)consent`)

// consentRecords reports (DP016) consent-based purposes with nothing that
// could prove consent: the Data Fiduciary bears that burden (s.6(10)).
func (a *analyzer) consentRecords() {
	cfg := a.in.Config
	if cfg == nil {
		return
	}
	var consentPurposes []string
	for _, p := range cfg.Purposes {
		if p.Basis == "consent" {
			consentPurposes = append(consentPurposes, p.ID)
		}
	}
	if len(consentPurposes) == 0 {
		return
	}
	declared := strings.TrimSpace(cfg.Organisation.ConsentRecords)
	for _, s := range a.in.Stores {
		if consentStore.MatchString(s.Name) {
			return
		}
		if declared != "" {
			if ok, _ := filepath.Match(strings.ToLower(declared), strings.ToLower(s.Name)); ok {
				return
			}
		}
	}
	if declared != "" && !strings.ContainsAny(declared, "*?[") {
		return // an external system, e.g. a registered Consent Manager
	}
	a.add("DP016", Medium, config.FileName, 0, "consent-records",
		fmt.Sprintf("Purposes %s rely on consent, but no consent record store was found in the code and none is declared. Section 6(10) puts the burden of proving consent on the Data Fiduciary: keep who consented, to which notice and purpose, when, and any withdrawal, and record where under organisation.consent_records.", strings.Join(consentPurposes, ", ")))
}

// significant reports (DP017) missing Significant Data Fiduciary duties.
func (a *analyzer) significant() {
	cfg := a.in.Config
	if cfg == nil || !cfg.Organisation.SignificantDataFiduciary {
		return
	}
	if strings.TrimSpace(cfg.Organisation.DPO) == "" {
		a.add("DP017", High, config.FileName, 0, "sdf|dpo",
			"A Significant Data Fiduciary must appoint a Data Protection Officer based in India (s.10(2)(a)); organisation.dpo is empty.")
	}
	for _, it := range []struct {
		key  string
		attn config.Attn
		what string
	}{{"dpia", cfg.SDF.DPIA, "a periodic Data Protection Impact Assessment (s.10(2)(c))"}, {"audit", cfg.SDF.Audit, "a periodic audit by an independent data auditor (s.10(2)(b))"}} {
		if !a.evidenceExists(it.attn.Evidence) {
			a.add("DP017", Medium, config.FileName, 0, "sdf|"+it.key,
				fmt.Sprintf("A Significant Data Fiduciary must carry out %s; add evidence under sdf.%s in dpdpward.yaml.", it.what, it.key))
		}
	}
}

func (a *analyzer) evidenceExists(evs []string) bool {
	for _, ev := range evs {
		if strings.HasPrefix(ev, "https://") {
			return true
		}
		if _, err := os.Stat(filepath.Join(a.in.Root, ev)); err == nil {
			return true
		}
	}
	return false
}

func labels(els []model.Element) string {
	seen := map[string]bool{}
	var out []string
	for _, e := range els {
		if !seen[e.Label] {
			seen[e.Label] = true
			out = append(out, e.Label)
		}
	}
	if len(out) > 4 {
		return strings.Join(out[:4], ", ") + fmt.Sprintf(" and %d more", len(out)-4)
	}
	return strings.Join(out, ", ")
}

func appendUnique(xs []string, s string) []string {
	for _, x := range xs {
		if x == s {
			return xs
		}
	}
	return append(xs, s)
}

// Deadline is one breach-response clock.
type Deadline struct {
	Who      string    `json:"who"`
	What     string    `json:"what"`
	Due      time.Time `json:"due"`
	Relative string    `json:"relative"`
	Source   string    `json:"source"`
}

// BreachClock computes the notification deadlines from the moment the
// organisation became aware of a personal data breach.
func BreachClock(aware time.Time) []Deadline {
	return []Deadline{
		{Who: "CERT-In", What: "Report the cyber security incident", Due: aware.Add(6 * time.Hour), Relative: "within 6 hours of noticing", Source: "CERT-In Directions under s.70B(6) IT Act, 28 April 2022"},
		{Who: "Data Protection Board", What: "Initial intimation: description, nature, extent, timing, location and likely impact", Due: aware, Relative: "without delay", Source: "DPDP Rules 2025, Rule 7(2)(a)"},
		{Who: "Each affected Data Principal", What: "Plain-language notice: what happened, likely consequences, mitigation, steps they can take, contact", Due: aware, Relative: "without delay", Source: "DPDP Rules 2025, Rule 7(1)"},
		{Who: "Data Protection Board", What: "Detailed report: facts, cause, mitigation, findings about the person responsible, remedial measures, notices sent", Due: aware.Add(72 * time.Hour), Relative: "within 72 hours (or longer if the Board allows on written request)", Source: "DPDP Rules 2025, Rule 7(2)(b)"},
	}
}
