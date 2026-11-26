// Command dpdpward maps personal data across a codebase for India's DPDP
// Act, 2023: where it lives, which purpose covers it, and whether the DPDP
// Rules, 2025 Rule 6 security safeguards are evidenced. It reads code only,
// never databases, and makes no network calls.
package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"path/filepath"
	"runtime/debug"
	"sort"
	"strings"
	"time"

	"github.com/Breaktroughf1/dpdpward/internal/analysis"
	"github.com/Breaktroughf1/dpdpward/internal/classify"
	"github.com/Breaktroughf1/dpdpward/internal/config"
	"github.com/Breaktroughf1/dpdpward/internal/extract"
	"github.com/Breaktroughf1/dpdpward/internal/iac"
	"github.com/Breaktroughf1/dpdpward/internal/report"
)

var version = "dev"

func init() {
	if version != "dev" {
		return
	}
	if bi, ok := debug.ReadBuildInfo(); ok && bi.Main.Version != "" && bi.Main.Version != "(devel)" {
		version = bi.Main.Version
	}
}

const usage = `dpdpward — map personal data in code for India's DPDP Act

Usage:
  dpdpward scan      [--dir .] [--config dpdpward.yaml] [--format md|json|sarif|csv] [--fail-on SEV] [--baseline FILE]
  dpdpward init      [--dir .]                       write a starter dpdpward.yaml from the scan
  dpdpward ropa      [--dir .] [--format md|csv|json] Record of Processing Activities
  dpdpward evidence  [--dir .] [-o evidence.json] [--check]   Rule 6 safeguards evidence
  dpdpward breach    --aware "2027-06-01T10:30:00+05:30" [--dir .]   notification deadlines
  dpdpward baseline  [--dir .] [-o dpdpward-baseline.json]
  dpdpward rules | version

dpdpward reads source files only: no database connections, no network.
Exit codes: 0 ok, 1 threshold exceeded or new personal data since baseline, 2 error.
Not legal advice.
`

func main() {
	_, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()
	code, err := run(os.Args[1:], os.Stdout, os.Stderr)
	if err != nil {
		fmt.Fprintln(os.Stderr, "dpdpward:", err)
		if code == 0 {
			code = 2
		}
	}
	os.Exit(code)
}

type flags struct {
	fs                  *flag.FlagSet
	dir, cfg, out, fmt_ string
	failOn, baseline    string
	aware               string
	check               bool
	noValues            bool
	exclude             multi
}

type multi []string

func (m *multi) String() string     { return strings.Join(*m, ",") }
func (m *multi) Set(v string) error { *m = append(*m, v); return nil }

func newFlags(name string) *flags {
	f := &flags{fs: flag.NewFlagSet(name, flag.ContinueOnError)}
	f.fs.StringVar(&f.dir, "dir", ".", "root of the codebase to scan")
	f.fs.StringVar(&f.cfg, "config", "", "path to dpdpward.yaml (default <dir>/dpdpward.yaml)")
	f.fs.StringVar(&f.out, "o", "", "output file (default stdout)")
	f.fs.StringVar(&f.fmt_, "format", "md", "output format")
	f.fs.StringVar(&f.failOn, "fail-on", "none", "exit 1 if a finding at or above this severity exists")
	f.fs.StringVar(&f.baseline, "baseline", "", "baseline file: only new findings count, and new personal data fields fail")
	f.fs.StringVar(&f.aware, "aware", "", "breach: when the organisation became aware (RFC 3339, or 'now')")
	f.fs.BoolVar(&f.check, "check", false, "evidence: exit 1 unless every Rule 6 safeguard is attested with evidence (status pass)")
	f.fs.BoolVar(&f.noValues, "no-values", false, "skip scanning files for identifier values")
	f.fs.Var(&f.exclude, "exclude", "glob to exclude, e.g. \"test/**\" (repeatable; adds to dpdpward.yaml's exclude)")
	return f
}

func run(args []string, stdout, stderr io.Writer) (int, error) {
	if len(args) == 0 || args[0] == "-h" || args[0] == "--help" || args[0] == "help" {
		fmt.Fprint(stdout, usage)
		return 0, nil
	}
	cmd := args[0]
	switch cmd {
	case "version":
		fmt.Fprintln(stdout, "dpdpward", version)
		return 0, nil
	case "rules":
		for _, r := range report.Rules {
			fmt.Fprintf(stdout, "%s  %-42s %s\n", r.ID, r.Name, r.Short)
		}
		return 0, nil
	}
	f := newFlags(cmd)
	f.fs.SetOutput(stderr)
	if err := f.fs.Parse(args[1:]); err != nil {
		return 2, err
	}
	switch cmd {
	case "scan", "ropa", "evidence", "baseline", "init", "breach":
	default:
		fmt.Fprint(stderr, usage)
		return 2, fmt.Errorf("unknown command %q", cmd)
	}
	if cmd == "breach" {
		return breach(f, stdout)
	}
	if cmd == "init" {
		return initConfig(f, stdout, stderr)
	}
	res, err := scan(f)
	if err != nil {
		return 2, err
	}
	switch cmd {
	case "scan":
		return scanOut(f, res, stdout)
	case "ropa":
		return 0, write(f.out, stdout, func(w io.Writer) error {
			switch f.fmt_ {
			case "csv":
				return report.ROPACSV(w, res)
			case "json":
				return report.JSON(w, map[string]any{"organisation": res.Organisation, "purposes": res.ROPA, "stores_without_purpose": res.Unmapped})
			default:
				report.ROPAMarkdown(w, res, time.Now())
				return nil
			}
		})
	case "evidence":
		ev := evidence(f.dir, res)
		if err := write(f.out, stdout, func(w io.Writer) error { return report.JSON(w, ev) }); err != nil {
			return 2, err
		}
		if f.check {
			for _, s := range res.Safeguards {
				if s.Status != "pass" {
					return 1, nil
				}
			}
		}
		return 0, nil
	case "baseline":
		out := f.out
		if out == "" {
			out = "dpdpward-baseline.json"
		}
		return 0, write(out, stdout, func(w io.Writer) error { return report.JSON(w, makeBaseline(res)) })
	}
	return 2, nil
}

func scan(f *flags) (analysis.Result, error) {
	root := f.dir
	if st, err := os.Stat(root); err != nil || !st.IsDir() {
		return analysis.Result{}, fmt.Errorf("--dir %s is not a directory", root)
	}
	cfgPath := f.cfg
	if cfgPath == "" {
		cfgPath = filepath.Join(root, config.FileName)
	}
	cfg, err := config.Load(cfgPath)
	if err != nil {
		return analysis.Result{}, err
	}
	exclude := append([]string(nil), f.exclude...)
	if cfg != nil {
		exclude = append(exclude, cfg.Exclude...)
	}
	ex, err := extract.Walk(root, exclude)
	if err != nil {
		return analysis.Result{}, err
	}
	in := analysis.Input{Root: root, Config: cfg, Stores: ex.Stores, Elements: classify.Stores(ex.Stores), Skipped: ex.Skipped}
	if !f.noValues {
		vals, err := classify.Values(root, exclude, matchExclude)
		if err != nil {
			return analysis.Result{}, err
		}
		in.Values = vals
	}
	blocks, err := iac.Parse(root, func(rel string) bool { return matchExclude(rel, exclude) })
	if err != nil {
		return analysis.Result{}, err
	}
	in.IaC = iac.Evaluate(blocks)
	return analysis.Analyze(in), nil
}

func matchExclude(rel string, patterns []string) bool {
	for _, p := range patterns {
		if ok, _ := filepath.Match(p, rel); ok {
			return true
		}
		if strings.HasSuffix(p, "/**") && strings.HasPrefix(rel+"/", strings.TrimSuffix(p, "**")) {
			return true
		}
	}
	return false
}

func scanOut(f *flags, res analysis.Result, stdout io.Writer) (int, error) {
	gate := res.Findings
	newFields := 0
	if f.baseline != "" {
		b, err := readBaseline(f.baseline)
		if err != nil {
			return 2, err
		}
		gate, newFields = diffBaseline(res, b)
	}
	err := write(f.out, stdout, func(w io.Writer) error {
		switch f.fmt_ {
		case "md", "markdown":
			report.Markdown(w, res)
			if f.baseline != "" {
				fmt.Fprintf(w, "\n**Baseline:** %d new finding(s), %d new personal data field(s) since %s.\n", len(gate), newFields, f.baseline)
			}
		case "json":
			return report.JSON(w, res)
		case "sarif":
			return report.SARIF(w, res, version)
		case "csv":
			return report.DataMapCSV(w, res)
		default:
			return fmt.Errorf("unknown format %q", f.fmt_)
		}
		return nil
	})
	if err != nil {
		return 2, err
	}
	if newFields > 0 {
		return 1, nil
	}
	if f.failOn != "none" {
		min, err := analysis.ParseSeverity(f.failOn)
		if err != nil {
			return 2, err
		}
		for _, fd := range gate {
			if fd.Severity >= min {
				return 1, nil
			}
		}
	}
	return 0, nil
}

// Baseline is an approved data map and finding set.
type Baseline struct {
	Version  int               `json:"version"`
	Fields   []string          `json:"personal_data_fields"`
	Findings map[string]string `json:"findings"`
}

func elementKey(store, field, category string) string {
	return store + "." + field + " (" + category + ")"
}

func makeBaseline(r analysis.Result) Baseline {
	b := Baseline{Version: 1, Findings: map[string]string{}}
	for _, e := range r.Elements {
		b.Fields = append(b.Fields, elementKey(e.Store, e.Field, e.Category))
	}
	sort.Strings(b.Fields)
	for _, f := range r.Findings {
		b.Findings[f.Fingerprint] = f.RuleID
	}
	return b
}

func readBaseline(p string) (Baseline, error) {
	var b Baseline
	data, err := os.ReadFile(p)
	if err != nil {
		return b, err
	}
	if err := json.Unmarshal(data, &b); err != nil {
		return b, fmt.Errorf("%s: %w", p, err)
	}
	return b, nil
}

func diffBaseline(r analysis.Result, b Baseline) ([]analysis.Finding, int) {
	var gate []analysis.Finding
	for _, f := range r.Findings {
		if _, ok := b.Findings[f.Fingerprint]; !ok {
			gate = append(gate, f)
		}
	}
	known := map[string]bool{}
	for _, k := range b.Fields {
		known[k] = true
	}
	n := 0
	for _, e := range r.Elements {
		if !known[elementKey(e.Store, e.Field, e.Category)] {
			n++
		}
	}
	return gate, n
}

// Evidence is the machine-checkable Rule 6 evidence record.
type Evidence struct {
	Schema       string               `json:"schema"`
	Tool         string               `json:"tool"`
	GeneratedAt  time.Time            `json:"generated_at"`
	Commit       string               `json:"git_commit,omitempty"`
	Organisation string               `json:"organisation,omitempty"`
	Safeguards   []analysis.Safeguard `json:"safeguards"`
	DataMap      map[string]int       `json:"data_map"`
	Findings     map[string]int       `json:"findings_by_severity"`
	Purposes     int                  `json:"purposes"`
	Unmapped     []string             `json:"stores_without_purpose,omitempty"`
	Disclaimer   string               `json:"disclaimer"`
}

func evidence(root string, r analysis.Result) Evidence {
	ev := Evidence{Schema: "https://github.com/Breaktroughf1/dpdpward/blob/main/docs/evidence.md#v1", Tool: "dpdpward " + version,
		GeneratedAt: time.Now().UTC(), Commit: gitCommit(root), Organisation: r.Organisation, Safeguards: r.Safeguards,
		DataMap: map[string]int{}, Findings: map[string]int{}, Purposes: len(r.ROPA), Unmapped: r.Unmapped, Disclaimer: report.Disclaimer}
	stores := map[string]bool{}
	for _, e := range r.Elements {
		stores[e.Store] = true
		ev.DataMap["fields_"+e.Sensitivity]++
	}
	ev.DataMap["fields"] = len(r.Elements)
	ev.DataMap["stores"] = len(stores)
	ev.DataMap["identifier_values_in_files"] = len(r.Values)
	for _, f := range r.Findings {
		ev.Findings[f.SeverityStr]++
	}
	return ev
}

// gitCommit reads HEAD without running git.
func gitCommit(root string) string {
	head, err := os.ReadFile(filepath.Join(root, ".git", "HEAD"))
	if err != nil {
		return ""
	}
	h := strings.TrimSpace(string(head))
	if !strings.HasPrefix(h, "ref: ") {
		return h
	}
	ref := strings.TrimPrefix(h, "ref: ")
	if b, err := os.ReadFile(filepath.Join(root, ".git", filepath.FromSlash(ref))); err == nil {
		return strings.TrimSpace(string(b))
	}
	if packed, err := os.ReadFile(filepath.Join(root, ".git", "packed-refs")); err == nil {
		for _, l := range strings.Split(string(packed), "\n") {
			if strings.HasSuffix(l, " "+ref) {
				return strings.Fields(l)[0]
			}
		}
	}
	return ""
}

func breach(f *flags, stdout io.Writer) (int, error) {
	if f.aware == "" {
		return 2, errors.New("--aware is required (RFC 3339 time, e.g. 2027-06-01T10:30:00+05:30, or 'now')")
	}
	var aware time.Time
	if f.aware == "now" {
		aware = time.Now().In(ist())
	} else {
		t, err := time.Parse(time.RFC3339, f.aware)
		if err != nil {
			return 2, fmt.Errorf("--aware: %w", err)
		}
		aware = t
	}
	var res *analysis.Result
	contacts := map[string]string{}
	if st, err := os.Stat(f.dir); err == nil && st.IsDir() {
		f.noValues = true
		if r, err := scan(f); err == nil {
			res = &r
		}
		cfgPath := f.cfg
		if cfgPath == "" {
			cfgPath = filepath.Join(f.dir, config.FileName)
		}
		if cfg, err := config.Load(cfgPath); err == nil && cfg != nil {
			contacts["grievance"] = cfg.Organisation.GrievanceContact
			contacts["dpo"] = cfg.Organisation.DPO
			contacts["cert-in"] = cfg.Organisation.CertInContact
		}
	}
	ds := analysis.BreachClock(aware)
	return 0, write(f.out, stdout, func(w io.Writer) error {
		if f.fmt_ == "json" {
			return report.JSON(w, map[string]any{"aware": aware, "deadlines": ds})
		}
		report.BreachMarkdown(w, aware, ds, res, contacts)
		return nil
	})
}

func ist() *time.Location {
	if l, err := time.LoadLocation("Asia/Kolkata"); err == nil {
		return l
	}
	return time.FixedZone("IST", 5*3600+1800)
}

func initConfig(f *flags, stdout, stderr io.Writer) (int, error) {
	path := f.cfg
	if path == "" {
		path = filepath.Join(f.dir, config.FileName)
	}
	if _, err := os.Stat(path); err == nil {
		return 2, fmt.Errorf("%s already exists; edit it instead", path)
	}
	f.noValues = true
	res, err := scan(f)
	if err != nil {
		return 2, err
	}
	var b bytes.Buffer
	b.WriteString(`# dpdpward configuration. Code shows where personal data is; this file says why.
# Fill in each purpose, then run: dpdpward scan
# Reference: https://github.com/Breaktroughf1/dpdpward/blob/main/docs/config.md
version: 1

organisation:
  name: ""                 # the Data Fiduciary
  grievance_contact: ""    # who answers Data Principals' requests and grievances
  dpo: ""                  # Data Protection Officer (Significant Data Fiduciaries)
  cert_in_contact: ""      # point of contact for CERT-In incident reports

exclude:                   # paths not to scan, e.g. test fixtures with synthetic data
  # - "test/**"

purposes:
  # One entry per purpose of processing. Every store with personal data must
  # be covered by at least one purpose. These stores were found by the scan:
  - id: unassigned
    description: "TODO: describe the purpose, then split stores into real purposes"
    basis: ""              # consent | legitimate-use
    legitimate_use: ""     # the section 7 clause, when basis is legitimate-use
    data_principals: []    # e.g. [customers, employees]
    retention: ""          # when the data is erased, e.g. "3 years after account closure"
    processors: []         # e.g. ["AWS ap-south-1 (hosting)"]
    transfers_outside_india: []
    children: false
    stores:
`)
	_, names := groupStores(res)
	for _, n := range names {
		fmt.Fprintf(&b, "      - %q\n", n)
	}
	if len(names) == 0 {
		b.WriteString("      []\n")
	}
	b.WriteString(`
children:
  verifiable_consent: false   # section 9: verifiable consent of a parent or lawful guardian
  mechanism: ""

safeguards:
  # DPDP Rules 2025, Rule 6(1). Cite evidence (repo paths or https URLs) for
  # what code cannot show. Without evidence a safeguard is never reported as met.
  encryption: { evidence: [] }
  access_control: { evidence: [] }
  logging: { evidence: [] }
  backups: { evidence: [] }
  log_retention: { evidence: [] }
  processor_contracts: { evidence: [] }
  organisational: { evidence: [] }

ignore: []
  # - { store: audit_log, field: actor_email, reason: "staff work e-mail, covered by HR purpose" }
`)
	if err := os.WriteFile(path, b.Bytes(), 0o644); err != nil {
		return 2, err
	}
	fmt.Fprintf(stderr, "wrote %s with %d store(s) holding personal data; describe each purpose, then run dpdpward scan\n", path, len(names))
	return 0, nil
}

func groupStores(r analysis.Result) (map[string]bool, []string) {
	m := map[string]bool{}
	for _, e := range r.Elements {
		m[e.Store] = true
	}
	var names []string
	for n := range m {
		names = append(names, n)
	}
	sort.Strings(names)
	return m, names
}

func write(path string, stdout io.Writer, f func(io.Writer) error) error {
	if path == "" || path == "-" {
		return f(stdout)
	}
	var buf bytes.Buffer
	if err := f(&buf); err != nil {
		return err
	}
	return os.WriteFile(path, buf.Bytes(), 0o644)
}
