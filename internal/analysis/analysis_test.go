package analysis

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/Breaktroughf1/dpdpward/internal/classify"
	"github.com/Breaktroughf1/dpdpward/internal/config"
	"github.com/Breaktroughf1/dpdpward/internal/iac"
	"github.com/Breaktroughf1/dpdpward/internal/model"
)

func input(t *testing.T, cfg *config.Config, checks []iac.Check) Input {
	t.Helper()
	stores := []model.Store{
		{Name: "users", Kind: "sql-table", File: "db.sql", Line: 1, Fields: []model.Field{{Name: "email", Line: 2}, {Name: "aadhaar_number", Line: 3}, {Name: "dob", Line: 4}}},
		{Name: "orders", Kind: "sql-table", File: "db.sql", Line: 10, Fields: []model.Field{{Name: "amount", Line: 11}}},
	}
	return Input{Root: t.TempDir(), Config: cfg, Stores: stores, Elements: classify.Stores(stores), IaC: checks}
}

func rules(r Result) map[string]int {
	m := map[string]int{}
	for _, f := range r.Findings {
		m[f.RuleID]++
	}
	return m
}

func status(r Result, key string) string {
	for _, s := range r.Safeguards {
		if s.Key == key {
			return s.Status
		}
	}
	return ""
}

func TestNoConfigFailsSafe(t *testing.T) {
	r := Analyze(input(t, nil, nil))
	got := rules(r)
	if got["DP001"] != 1 || got["DP002"] != 1 || got["DP004"] != 1 {
		t.Errorf("rules %v", got)
	}
	for _, s := range r.Safeguards {
		if s.Status != "unknown" {
			t.Errorf("without evidence %s must be unknown, got %s", s.Key, s.Status)
		}
	}
	if got["DP009"] != 7 {
		t.Errorf("every unevidenced safeguard needs a DP009, got %d", got["DP009"])
	}
}

func TestPurposesAndSafeguards(t *testing.T) {
	cfg := &config.Config{
		Purposes: []config.Purpose{
			{ID: "accounts", Basis: "consent", Retention: "3 years", Stores: []string{"us*"}},
			{ID: "ghost", Basis: "legitimate-use", Stores: []string{"missing_table"}},
		},
		Children:   config.Children{VerifiableConsent: true, Mechanism: "DigiLocker age token"},
		Safeguards: map[string]config.Attn{"organisational": {Evidence: []string{"policy.md"}}, "logging": {Evidence: []string{"nope.md"}}},
	}
	in := input(t, cfg, []iac.Check{
		{Safeguard: "encryption", Status: "pass", Resource: "aws_rds_cluster.a"},
		{Safeguard: "backups", Status: "pass", Resource: "aws_rds_cluster.a"},
		{Safeguard: "backups", Status: "unknown", Resource: "aws_db_instance.b"},
		{Safeguard: "log_retention", Status: "fail", Resource: "aws_cloudwatch_log_group.c", Detail: "30 days"},
	})
	if err := os.WriteFile(filepath.Join(in.Root, "policy.md"), []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	r := Analyze(in)
	got := rules(r)
	if got["DP001"] != 0 {
		t.Error("users is covered by the accounts purpose (glob)")
	}
	if got["DP004"] != 0 {
		t.Error("a recorded verifiable-consent mechanism clears DP004")
	}
	if got["DP012"] != 1 || got["DP006"] != 1 || got["DP005"] != 1 {
		t.Errorf("ghost purpose should be stale, lack a legitimate-use clause and retention: %v", got)
	}
	if got["DP010"] != 1 {
		t.Errorf("missing evidence file must be reported: %v", got)
	}
	want := map[string]string{
		"organisational": "pass",    // attested with an existing file
		"encryption":     "partial", // infrastructure only
		"backups":        "unknown", // one undecided check blocks partial
		"log_retention":  "fail",
		"logging":        "unknown", // cited evidence does not exist
	}
	for k, v := range want {
		if s := status(r, k); s != v {
			t.Errorf("%s: got %s want %s", k, s, v)
		}
	}
	if len(r.ROPA) != 2 || len(r.ROPA[0].Categories) == 0 {
		t.Errorf("ROPA: %+v", r.ROPA)
	}
}

func TestIgnoreNeedsReason(t *testing.T) {
	cfg := &config.Config{Ignore: []config.Ignore{{Store: "users", Field: "email", Reason: "test account"}, {Store: "users", Field: "dob"}}}
	r := Analyze(input(t, cfg, nil))
	for _, e := range r.Elements {
		if e.Field == "email" {
			t.Error("ignored field with a reason must be dropped")
		}
	}
	found := false
	for _, e := range r.Elements {
		if e.Field == "dob" {
			found = true
		}
	}
	if !found || rules(r)["DP013"] != 1 {
		t.Error("ignore without a reason must not apply and must be reported")
	}
}

func TestBreachClock(t *testing.T) {
	aware := time.Date(2027, 6, 1, 10, 30, 0, 0, time.FixedZone("IST", 19800))
	ds := BreachClock(aware)
	due := map[string]time.Duration{}
	for _, d := range ds {
		due[d.Who+"|"+d.Relative] = d.Due.Sub(aware)
	}
	if due["CERT-In|within 6 hours of noticing"] != 6*time.Hour {
		t.Error("CERT-In deadline must be 6 hours")
	}
	if due["Data Protection Board|within 72 hours (or longer if the Board allows on written request)"] != 72*time.Hour {
		t.Error("Board detailed report must be 72 hours")
	}
}

func TestFingerprintsStable(t *testing.T) {
	a := Analyze(input(t, nil, nil))
	b := Analyze(input(t, nil, nil))
	for i := range a.Findings {
		if a.Findings[i].Fingerprint != b.Findings[i].Fingerprint {
			t.Fatal("fingerprints must be deterministic")
		}
	}
}

func TestConsentAndSDF(t *testing.T) {
	cfg := &config.Config{Purposes: []config.Purpose{{ID: "marketing", Basis: "consent", Retention: "1y", Stores: []string{"users", "orders"}}}}
	cfg.Organisation.SignificantDataFiduciary = true
	cfg.SDF.Audit = config.Attn{Evidence: []string{"https://auditor.example/report"}}
	got := rules(Analyze(input(t, cfg, nil)))
	if got["DP016"] != 1 {
		t.Errorf("consent basis with no consent store must raise DP016: %v", got)
	}
	if got["DP017"] != 2 {
		t.Errorf("SDF without DPO and DPIA evidence must raise two DP017 (audit is evidenced): %v", got)
	}
	in := input(t, cfg, nil)
	in.Stores = append(in.Stores, model.Store{Name: "user_consents", Kind: "sql-table"})
	if rules(Analyze(in))["DP016"] != 0 {
		t.Error("a consent store in the code clears DP016")
	}
	cfg2 := *cfg
	cfg2.Organisation.ConsentRecords = "Registered Consent Manager (example)"
	if rules(Analyze(input(t, &cfg2, nil)))["DP016"] != 0 {
		t.Error("a declared external consent system clears DP016")
	}
}
