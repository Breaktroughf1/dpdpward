package main

import (
	"bytes"
	"encoding/json"
	"math/rand"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Breaktroughf1/dpdpward/internal/classify"
)

const demo = "../../examples/demo-app"

func dw(t *testing.T, args ...string) (int, string) {
	t.Helper()
	var out, errb bytes.Buffer
	code, err := run(args, &out, &errb)
	if err != nil {
		t.Logf("%v: %v", args, err)
		if code == 0 {
			code = 2
		}
	}
	return code, out.String()
}

func TestDemoScan(t *testing.T) {
	code, out := dw(t, "scan", "--dir", demo, "--format", "json")
	if code != 0 {
		t.Fatalf("exit %d", code)
	}
	var r struct {
		Elements []struct{ Store, Field, Category string } `json:"personal_data"`
		Findings []struct {
			RuleID string `json:"rule_id"`
		} `json:"findings"`
	}
	if err := json.Unmarshal([]byte(out), &r); err != nil {
		t.Fatal(err)
	}
	got := map[string]int{}
	for _, f := range r.Findings {
		got[f.RuleID]++
	}
	for rule, n := range map[string]int{"DP001": 3, "DP002": 1, "DP003": 1, "DP004": 1, "DP005": 1, "DP006": 1, "DP010": 1, "DP015": 1} {
		if got[rule] != n {
			t.Errorf("%s: got %d want %d (all %v)", rule, got[rule], n, got)
		}
	}
	for _, e := range r.Elements {
		if e.Field == "email_verified" || e.Store == "Course" || e.Field == "school" {
			t.Errorf("not personal data: %s.%s", e.Store, e.Field)
		}
	}
	if code, _ := dw(t, "scan", "--dir", demo, "--fail-on", "critical"); code != 1 {
		t.Errorf("stored CVV is critical; --fail-on critical must exit 1, got %d", code)
	}
}

func TestFormats(t *testing.T) {
	for _, f := range []string{"md", "sarif", "csv"} {
		if code, out := dw(t, "scan", "--dir", demo, "--format", f); code != 0 || len(out) < 200 {
			t.Errorf("format %s: exit %d, %d bytes", f, code, len(out))
		}
	}
	for _, f := range []string{"md", "csv", "json"} {
		if code, out := dw(t, "ropa", "--dir", demo, "--format", f); code != 0 || !strings.Contains(out, "lending") {
			t.Errorf("ropa %s: %d", f, code)
		}
	}
	if code, out := dw(t, "breach", "--aware", "2027-06-01T10:30:00+05:30", "--dir", demo); code != 0 || !strings.Contains(out, "Fri 4 Jun 10:30") || !strings.Contains(out, "16:30") {
		t.Errorf("breach clock: %d\n%s", code, out)
	}
	if code, _ := dw(t, "breach"); code != 2 {
		t.Error("breach without --aware must be an error")
	}
	if code, _ := dw(t, "evidence", "--dir", demo, "--check"); code != 1 {
		t.Error("evidence --check must fail while safeguards are not all attested")
	}
	if code, _ := dw(t, "rules"); code != 0 {
		t.Error("rules")
	}
	if code, _ := dw(t, "nope"); code != 2 {
		t.Error("unknown command must exit 2")
	}
}

func copyDir(t *testing.T, src string) string {
	t.Helper()
	dst := t.TempDir()
	err := filepath.Walk(src, func(p string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		rel, _ := filepath.Rel(src, p)
		if info.IsDir() {
			return os.MkdirAll(filepath.Join(dst, rel), 0o755)
		}
		b, err := os.ReadFile(p)
		if err != nil {
			return err
		}
		return os.WriteFile(filepath.Join(dst, rel), b, 0o644)
	})
	if err != nil {
		t.Fatal(err)
	}
	return dst
}

func TestBaselineDrift(t *testing.T) {
	dir := copyDir(t, demo)
	b := filepath.Join(t.TempDir(), "b.json")
	if code, _ := dw(t, "baseline", "--dir", dir, "-o", b); code != 0 {
		t.Fatal("baseline")
	}
	if code, _ := dw(t, "scan", "--dir", dir, "--baseline", b, "--fail-on", "high"); code != 0 {
		t.Errorf("unchanged code must pass against its baseline, got %d", code)
	}
	f, _ := os.OpenFile(filepath.Join(dir, "db/schema.sql"), os.O_APPEND|os.O_WRONLY, 0)
	_, _ = f.WriteString("\nALTER TABLE customers ADD COLUMN passport_number VARCHAR(9);\n")
	_ = f.Close()
	if code, out := dw(t, "scan", "--dir", dir, "--baseline", b); code != 1 || !strings.Contains(out, "1 new personal data field") {
		t.Errorf("a new personal data field must fail the gate: %d", code)
	}
}

func TestInit(t *testing.T) {
	dir := copyDir(t, demo)
	_ = os.Remove(filepath.Join(dir, "dpdpward.yaml"))
	if code, _ := dw(t, "init", "--dir", dir); code != 0 {
		t.Fatal("init failed")
	}
	data, _ := os.ReadFile(filepath.Join(dir, "dpdpward.yaml"))
	for _, s := range []string{`"customers"`, `"saved_cards"`, "verifiable_consent"} {
		if !strings.Contains(string(data), s) {
			t.Errorf("init output lacks %s", s)
		}
	}
	// The generated file must load, and every store must then be mapped.
	code, out := dw(t, "scan", "--dir", dir, "--format", "json")
	if code != 0 || strings.Contains(out, `"DP001"`) {
		t.Errorf("init should map every store to the unassigned purpose: %d", code)
	}
	if code, _ := dw(t, "init", "--dir", dir); code != 2 {
		t.Error("init must refuse to overwrite")
	}
}

func TestBadConfigIsAnError(t *testing.T) {
	dir := t.TempDir()
	_ = os.WriteFile(filepath.Join(dir, "dpdpward.yaml"), []byte("version: 1\npurposes:\n  - id: a\n    retension: oops\n"), 0o644)
	if code, _ := dw(t, "scan", "--dir", dir); code != 2 {
		t.Error("a misspelt key must be an error, not silently ignored")
	}
}

func TestIdentifierValues(t *testing.T) {
	dir := t.TempDir()
	r := rand.New(rand.NewSource(1))
	base := []byte{byte('2' + r.Intn(8))}
	for len(base) < 11 {
		base = append(base, byte('0'+r.Intn(10)))
	}
	aadhaar := string(base) + string(classify.VerhoeffDigit(string(base)))
	_ = os.MkdirAll(filepath.Join(dir, "test"), 0o755)
	_ = os.WriteFile(filepath.Join(dir, "test/seed.csv"), []byte("name,aadhaar\nx,"+aadhaar+"\n"), 0o644)
	code, out := dw(t, "scan", "--dir", dir, "--format", "json")
	if code != 0 || !strings.Contains(out, `"DP007"`) || strings.Contains(out, aadhaar) {
		t.Errorf("value must be found and redacted: %d", code)
	}
	if _, out := dw(t, "scan", "--dir", dir, "--format", "json", "--exclude", "test/**"); strings.Contains(out, `"DP007"`) {
		t.Error("--exclude must skip the excluded path")
	}
	if _, out := dw(t, "scan", "--dir", dir, "--format", "json", "--no-values"); strings.Contains(out, `"DP007"`) {
		t.Error("--no-values must skip value scanning")
	}
}

func TestDemoAndHTML(t *testing.T) {
	code, out := dw(t, "demo")
	if code != 0 || !strings.Contains(out, "Record of Processing Activities") || !strings.Contains(out, "DP003") {
		t.Fatalf("demo: %d", code)
	}
	code, html := dw(t, "demo", "--format", "html")
	if code != 0 || !strings.HasPrefix(html, "<!doctype html>") || !strings.Contains(html, "Rule 6 security safeguards") || strings.Contains(html, "<script") {
		t.Fatalf("demo html: %d", code)
	}
	if code, out := dw(t, "scan", "--dir", demo, "--format", "html"); code != 0 || !strings.Contains(out, "Record of Processing Activities") {
		t.Errorf("scan html: %d", code)
	}
}
