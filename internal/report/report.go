// Package report renders dpdpward results.
package report

import (
	"encoding/csv"
	"encoding/json"
	"fmt"
	"io"
	"sort"
	"strings"
	"time"

	"github.com/Breaktroughf1/dpdpward/internal/analysis"
)

// Disclaimer is printed on every human-readable output.
const Disclaimer = "dpdpward is a technical aid, not legal advice. It finds personal data and safeguard evidence in code; it cannot judge lawfulness. Verify obligations against the DPDP Act, 2023, the DPDP Rules, 2025 (official Gazette text) and your counsel."

// Rule describes a rule for SARIF and docs.
type Rule struct{ ID, Name, Short, Help string }

// Rules lists every rule.
var Rules = []Rule{
	{"DP001", "personal-data-without-purpose", "Personal data with no declared purpose", "Map the store to a purpose in dpdpward.yaml with a lawful basis and retention period, or stop collecting the data."},
	{"DP002", "aadhaar-number-stored", "Aadhaar numbers stored", "Store Aadhaar only if permitted, encrypted in an Aadhaar Data Vault; otherwise keep a reference token or the last four digits."},
	{"DP003", "card-security-code-stored", "Card CVV or PIN stored", "Never store CVV/CVC or PINs after authorisation. Remove the field."},
	{"DP004", "children-data-without-verifiable-consent", "Children's data indicators without a verifiable-consent mechanism", "Record the verifiable parental consent mechanism (section 9) under children: in dpdpward.yaml."},
	{"DP005", "purpose-without-retention", "Purpose with no retention period", "State when data for the purpose is erased (section 8(7))."},
	{"DP006", "purpose-without-lawful-basis", "Purpose with no lawful basis", "Set basis: consent or legitimate-use (with the section 7 clause)."},
	{"DP007", "identifier-value-in-repository", "Real-looking identifier in code, fixtures or logs", "Replace with synthetic values and purge the value from version history."},
	{"DP008", "safeguard-failed", "Infrastructure setting contradicts a Rule 6 safeguard", "Fix the setting (encryption, public access, backups, one-year log retention)."},
	{"DP009", "safeguard-unevidenced", "No evidence for a Rule 6 safeguard", "Add an attestation with evidence under safeguards: in dpdpward.yaml; unproven safeguards are never reported as met."},
	{"DP010", "missing-evidence-file", "Cited evidence does not exist", "Fix the path or add the document."},
	{"DP011", "high-sensitivity-data", "Health, biometric or similar data stored", "Minimise, restrict access, and weigh it in any impact assessment."},
	{"DP012", "stale-purpose-record", "Purpose lists stores not found in code", "Update the purpose's stores list."},
	{"DP013", "ignore-without-reason", "Ignore entry without a reason", "Record why the field is not personal data."},
	{"DP014", "cross-border-transfer", "Transfer outside India declared", "Check each country against any restriction notified under section 16."},
	{"DP016", "consent-not-evidenced", "Consent relied on, but no consent records", "Keep consent records (who, notice, purpose, time, withdrawal) and name the store or system under organisation.consent_records (s.6(10))."},
	{"DP017", "significant-data-fiduciary-duties", "Significant Data Fiduciary duty not evidenced", "Appoint a DPO in India and evidence the periodic DPIA and independent audit (s.10)."},
	{"DP015", "contact-missing", "Grievance or CERT-In contact not recorded", "Record contacts under organisation: in dpdpward.yaml."},
}

// JSON writes v as indented JSON.
func JSON(w io.Writer, v any) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(v)
}

func esc(s string) string {
	return strings.NewReplacer("|", "\\|", "*", "\\*", "_", "\\_").Replace(s)
}

// Markdown writes the full scan report.
func Markdown(w io.Writer, r analysis.Result) {
	title := "dpdpward report"
	if r.Organisation != "" {
		title += ": " + r.Organisation
	}
	fmt.Fprintf(w, "# %s\n\n", title)
	counts := map[string]int{}
	for _, f := range r.Findings {
		counts[f.SeverityStr]++
	}
	stores := map[string]bool{}
	high := 0
	for _, e := range r.Elements {
		stores[e.Store] = true
		if e.Sensitivity == "high" {
			high++
		}
	}
	fmt.Fprintf(w, "**Personal data:** %d fields in %d stores (%d high-sensitivity) · %d identifier values in files\n\n", len(r.Elements), len(stores), high, len(r.Values))
	fmt.Fprintf(w, "**Findings:** %d critical · %d high · %d medium · %d low · %d info\n\n",
		counts["critical"], counts["high"], counts["medium"], counts["low"], counts["info"])
	if !r.ConfigFound {
		fmt.Fprint(w, "> **No dpdpward.yaml.** Purposes, lawful basis and retention are unknown, so every store with personal data is reported. Run `dpdpward init` to start one.\n\n")
	}

	fmt.Fprint(w, "## Rule 6 safeguards\n\n| Clause | Safeguard | Status | Evidence |\n|---|---|---|---|\n")
	for _, s := range r.Safeguards {
		var ev []string
		ev = append(ev, s.Evidence...)
		for _, c := range s.Checks {
			ev = append(ev, fmt.Sprintf("%s: %s (%s)", c.Status, c.Resource, c.File))
		}
		if len(ev) > 4 {
			ev = append(ev[:4], fmt.Sprintf("… %d more", len(ev)-4))
		}
		fmt.Fprintf(w, "| %s | %s | %s | %s |\n", s.Clause, s.Title, strings.ToUpper(s.Status), esc(strings.Join(ev, "<br>")))
	}

	fmt.Fprint(w, "\n## Data map\n\n")
	if len(r.Elements) == 0 {
		fmt.Fprint(w, "No personal data fields found in the scanned schemas and models.\n")
	}
	group := map[string][]int{}
	var order []string
	for i, e := range r.Elements {
		k := e.Store + "\x00" + e.File
		if _, ok := group[k]; !ok {
			order = append(order, k)
		}
		group[k] = append(group[k], i)
	}
	for _, k := range order {
		first := r.Elements[group[k][0]]
		fmt.Fprintf(w, "### `%s` (%s, `%s:%d`)\n\n| Field | Category | Sensitivity | Line |\n|---|---|---|---|\n", first.Store, first.StoreKind, first.File, storeLine(r, first.Store, first.File))
		for _, i := range group[k] {
			e := r.Elements[i]
			fmt.Fprintf(w, "| `%s` | %s | %s | %d |\n", e.Field, e.Label, e.Sensitivity, e.Line)
		}
		fmt.Fprintln(w)
	}
	if len(r.Values) > 0 {
		fmt.Fprint(w, "## Identifier values found in files\n\n| File | Line | Kind | Value (redacted) |\n|---|---|---|---|\n")
		for _, v := range r.Values {
			fmt.Fprintf(w, "| `%s` | %d | %s | `%s` |\n", v.File, v.Line, v.Kind, v.Redacted)
		}
		fmt.Fprintln(w)
	}
	fmt.Fprint(w, "## Findings\n\n")
	if len(r.Findings) == 0 {
		fmt.Fprint(w, "No findings.\n")
	}
	for _, f := range r.Findings {
		loc := ""
		if f.File != "" {
			loc = fmt.Sprintf(" — `%s", f.File)
			if f.Line > 0 {
				loc += fmt.Sprintf(":%d", f.Line)
			}
			loc += "`"
		}
		fmt.Fprintf(w, "- **%s** `%s`%s: %s\n", strings.ToUpper(f.SeverityStr), f.RuleID, loc, esc(f.Message))
	}
	if len(r.Gaps) > 0 {
		fmt.Fprint(w, "\n## Files not scanned\n\n")
		for _, g := range r.Gaps {
			fmt.Fprintf(w, "- %s\n", esc(g))
		}
	}
	fmt.Fprintf(w, "\n---\n%s\n", Disclaimer)
}

func storeLine(r analysis.Result, name, file string) int {
	for _, s := range r.Stores {
		if s.Name == name && s.File == file {
			return s.Line
		}
	}
	return 0
}

// DataMapCSV writes one row per personal data field.
func DataMapCSV(w io.Writer, r analysis.Result) error {
	cw := csv.NewWriter(w)
	_ = cw.Write([]string{"store", "store_kind", "field", "category", "label", "sensitivity", "confidence", "children_indicator", "file", "line"})
	for _, e := range r.Elements {
		_ = cw.Write([]string{e.Store, e.StoreKind, e.Field, e.Category, e.Label, e.Sensitivity, e.Confidence, fmt.Sprint(e.Children), e.File, fmt.Sprint(e.Line)})
	}
	cw.Flush()
	return cw.Error()
}

// ROPAMarkdown writes the Record of Processing Activities.
func ROPAMarkdown(w io.Writer, r analysis.Result, generated time.Time) {
	org := r.Organisation
	if org == "" {
		org = "(organisation not set)"
	}
	fmt.Fprintf(w, "# Record of Processing Activities\n\n**Data Fiduciary:** %s  \n**Generated:** %s from code and dpdpward.yaml\n\n", esc(org), generated.Format("2 January 2006"))
	if !r.ConfigFound {
		fmt.Fprint(w, "> No dpdpward.yaml: purposes are not declared. Run `dpdpward init`.\n\n")
	}
	for _, p := range r.ROPA {
		fmt.Fprintf(w, "## %s\n\n%s\n\n", esc(p.ID), esc(orDash(p.Description)))
		basis := orDash(p.Basis)
		if p.LegitimateUse != "" {
			basis += " (" + p.LegitimateUse + ")"
		}
		rows := [][2]string{
			{"Lawful basis", basis},
			{"Data Principals", orDash(strings.Join(p.DataPrincipals, ", "))},
			{"Personal data", orDash(strings.Join(p.Categories, ", "))},
			{"Stores", orDash(strings.Join(p.Stores, ", "))},
			{"Retention", orDash(p.Retention)},
			{"Processors", orDash(strings.Join(p.Processors, ", "))},
			{"Transfers outside India", orDash(strings.Join(p.Transfers, ", "))},
			{"Children's data", yesNo(p.Children)},
		}
		fmt.Fprint(w, "| | |\n|---|---|\n")
		for _, row := range rows {
			fmt.Fprintf(w, "| %s | %s |\n", row[0], esc(row[1]))
		}
		fmt.Fprintln(w)
	}
	if len(r.Unmapped) > 0 {
		fmt.Fprint(w, "## Personal data without a declared purpose\n\n")
		for _, u := range r.Unmapped {
			fmt.Fprintf(w, "- `%s`\n", u)
		}
		fmt.Fprintln(w)
	}
	fmt.Fprintf(w, "---\n%s\n", Disclaimer)
}

// ROPACSV writes the ROPA as CSV.
func ROPACSV(w io.Writer, r analysis.Result) error {
	cw := csv.NewWriter(w)
	_ = cw.Write([]string{"purpose", "description", "basis", "legitimate_use", "data_principals", "personal_data", "stores", "retention", "processors", "transfers_outside_india", "children"})
	for _, p := range r.ROPA {
		_ = cw.Write([]string{p.ID, p.Description, p.Basis, p.LegitimateUse, strings.Join(p.DataPrincipals, "; "),
			strings.Join(p.Categories, "; "), strings.Join(p.Stores, "; "), p.Retention, strings.Join(p.Processors, "; "),
			strings.Join(p.Transfers, "; "), yesNo(p.Children)})
	}
	for _, u := range r.Unmapped {
		_ = cw.Write([]string{"(none)", "", "", "", "", "", u, "", "", "", ""})
	}
	cw.Flush()
	return cw.Error()
}

// BreachMarkdown prints the breach clock.
func BreachMarkdown(w io.Writer, aware time.Time, ds []analysis.Deadline, r *analysis.Result, contacts map[string]string) {
	fmt.Fprintf(w, "# Personal data breach clock\n\n**Became aware:** %s\n\n| Due | Notify | What | Basis |\n|---|---|---|---|\n", aware.Format("Mon 2 Jan 2006 15:04 MST"))
	sort.SliceStable(ds, func(i, j int) bool { return ds[i].Due.Before(ds[j].Due) })
	for _, d := range ds {
		due := d.Due.Format("Mon 2 Jan 15:04 MST")
		if d.Due.Equal(aware) {
			due = "now (" + d.Relative + ")"
		} else {
			due += " (" + d.Relative + ")"
		}
		fmt.Fprintf(w, "| %s | %s | %s | %s |\n", due, d.Who, d.What, d.Source)
	}
	if len(contacts) > 0 {
		fmt.Fprint(w, "\n**Contacts on record:** ")
		var parts []string
		for _, k := range []string{"grievance", "dpo", "cert-in"} {
			if v := contacts[k]; v != "" {
				parts = append(parts, k+": "+v)
			}
		}
		fmt.Fprintln(w, strings.Join(parts, " · "))
	}
	if r != nil && len(r.Elements) > 0 {
		cats := map[string][]string{}
		for _, e := range r.Elements {
			cats[e.Label] = appendU(cats[e.Label], e.Store)
		}
		var keys []string
		for k := range cats {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		fmt.Fprint(w, "\n## Personal data that may be affected (from the code scan)\n\nUse this to scope the report. Narrow it to the systems actually involved.\n\n")
		for _, k := range keys {
			fmt.Fprintf(w, "- **%s**: %s\n", k, strings.Join(cats[k], ", "))
		}
	}
	fmt.Fprint(w, "\nThe Rule 7 breach duties commence on 13 May 2027 (18 months after notification). CERT-In reporting applies now.\n")
	fmt.Fprintf(w, "\n---\n%s\n", Disclaimer)
}

func appendU(xs []string, s string) []string {
	for _, x := range xs {
		if x == s {
			return xs
		}
	}
	return append(xs, s)
}

func orDash(s string) string {
	if strings.TrimSpace(s) == "" {
		return "—"
	}
	return s
}

func yesNo(b bool) string {
	if b {
		return "yes"
	}
	return "no"
}

// SARIF writes findings as SARIF 2.1.0.
func SARIF(w io.Writer, r analysis.Result, version string) error {
	type msg struct {
		Text string `json:"text"`
	}
	idx := map[string]int{}
	var rules []map[string]any
	for i, ru := range Rules {
		idx[ru.ID] = i
		rules = append(rules, map[string]any{"id": ru.ID, "name": ru.Name, "shortDescription": msg{ru.Short}, "help": msg{ru.Help},
			"helpUri":    "https://github.com/Breaktroughf1/dpdpward/blob/main/docs/rules.md#" + strings.ToLower(ru.ID),
			"properties": map[string]any{"tags": []string{"privacy", "dpdp", "compliance"}}})
	}
	results := []map[string]any{}
	for _, f := range r.Findings {
		uri := f.File
		if uri == "" {
			uri = "dpdpward.yaml"
		}
		line := f.Line
		if line < 1 {
			line = 1
		}
		level := "note"
		switch {
		case f.Severity >= analysis.High:
			level = "error"
		case f.Severity == analysis.Medium:
			level = "warning"
		}
		results = append(results, map[string]any{
			"ruleId": f.RuleID, "ruleIndex": idx[f.RuleID], "level": level, "message": msg{f.Message},
			"locations": []any{map[string]any{"physicalLocation": map[string]any{
				"artifactLocation": map[string]any{"uri": uri}, "region": map[string]any{"startLine": line}}}},
			"partialFingerprints": map[string]string{"dpdpward/v1": f.Fingerprint},
		})
	}
	return JSON(w, map[string]any{
		"$schema": "https://json.schemastore.org/sarif-2.1.0.json", "version": "2.1.0",
		"runs": []any{map[string]any{
			"tool": map[string]any{"driver": map[string]any{"name": "dpdpward", "version": version,
				"informationUri": "https://github.com/Breaktroughf1/dpdpward", "rules": rules}},
			"results": results,
		}},
	})
}
