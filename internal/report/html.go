package report

import (
	"html/template"
	"io"
	"strings"
	"time"

	"github.com/Breaktroughf1/dpdpward/internal/analysis"
	"github.com/Breaktroughf1/dpdpward/internal/model"
)

type htmlStore struct {
	Name, Kind, File string
	Elements         []model.Element
}

// HTML writes a single self-contained report (no external assets): data
// map, Rule 6 safeguards, ROPA and findings, printable to PDF.
func HTML(w io.Writer, r analysis.Result, title, version string, generated time.Time) error {
	counts := map[string]int{}
	for _, f := range r.Findings {
		counts[f.SeverityStr]++
	}
	var stores []htmlStore
	idx := map[string]int{}
	high := 0
	for _, e := range r.Elements {
		if e.Sensitivity == "high" {
			high++
		}
		k := e.Store + "\x00" + e.File
		i, ok := idx[k]
		if !ok {
			i = len(stores)
			idx[k] = i
			stores = append(stores, htmlStore{Name: e.Store, Kind: e.StoreKind, File: e.File})
		}
		stores[i].Elements = append(stores[i].Elements, e)
	}
	return dpTmpl.Execute(w, map[string]any{
		"Title": title, "Version": version, "Generated": generated, "R": r, "Counts": counts,
		"Stores": stores, "High": high, "Disclaimer": Disclaimer,
		"Sev": []string{"critical", "high", "medium", "low", "info"},
	})
}

var dpTmpl = template.Must(template.New("r").Funcs(template.FuncMap{
	"upper": strings.ToUpper,
	"join":  strings.Join,
	"date":  func(t time.Time) string { return t.Format("2 January 2006, 15:04 MST") },
}).Parse(`<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>{{.Title}}</title>
<style>
:root{--bg:#fff;--fg:#1f2328;--muted:#59636e;--line:#d1d9e0;--card:#f6f8fa;--crit:#82071e;--high:#cf222e;--med:#9a6700;--low:#0969da;--info:#59636e;--ok:#1a7f37}
@media (prefers-color-scheme:dark){:root{--bg:#0d1117;--fg:#e6edf3;--muted:#9198a1;--line:#3d444d;--card:#151b23;--crit:#ff7b72;--high:#f85149;--med:#d29922;--low:#4493f8;--info:#9198a1;--ok:#3fb950}}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--fg);font:15px/1.55 -apple-system,"Segoe UI",Helvetica,Arial,sans-serif}
main{max-width:1100px;margin:0 auto;padding:32px 16px 64px}h1{font-size:26px;margin:0 0 4px}h2{font-size:19px;margin:36px 0 12px;border-bottom:1px solid var(--line);padding-bottom:6px}h3{font-size:15px;margin:18px 0 6px}
.meta{color:var(--muted);font-size:13px}.cards{display:grid;grid-template-columns:repeat(auto-fit,minmax(130px,1fr));gap:10px;margin:20px 0}
.card{background:var(--card);border:1px solid var(--line);border-radius:8px;padding:12px}.card b{display:block;font-size:24px}
.critical{color:var(--crit)}.high{color:var(--high)}.medium{color:var(--med)}.low{color:var(--low)}.info{color:var(--info)}
.pass{color:var(--ok);font-weight:600}.fail{color:var(--high);font-weight:600}.partial{color:var(--med);font-weight:600}.unknown{color:var(--muted);font-weight:600}
table{width:100%;border-collapse:collapse;font-size:13.5px;margin:8px 0 18px}th,td{border:1px solid var(--line);padding:6px 8px;text-align:left;vertical-align:top}th{background:var(--card)}
code{font:12.5px ui-monospace,SFMono-Regular,Menlo,monospace;overflow-wrap:anywhere}.nw,.nw code{white-space:nowrap;overflow-wrap:normal}.scroll{overflow-x:auto}
.badge{font-weight:600;text-transform:uppercase;font-size:12px}.note{background:var(--card);border-left:4px solid var(--med);padding:10px 12px;border-radius:4px}
@media print{body{font-size:11.5px}main{padding:0}tr,.card{break-inside:avoid}}
</style></head><body><main>
<h1>{{.Title}}</h1>
<div class="meta">Generated {{date .Generated}} by dpdpward {{.Version}} from source code and dpdpward.yaml · no databases were read</div>
<div class="cards">
<div class="card"><b>{{len .R.Elements}}</b>personal data fields in {{len .Stores}} stores</div>
<div class="card"><b class="high">{{.High}}</b>high-sensitivity fields</div>
<div class="card"><b class="high">{{len .R.Unmapped}}</b>stores without a declared purpose</div>
{{range .Sev}}<div class="card"><b class="{{.}}">{{index $.Counts .}}</b>{{.}} findings</div>{{end}}
</div>
{{if not .R.ConfigFound}}<p class="note"><b>No dpdpward.yaml:</b> purposes, lawful basis and retention are not declared. Run <code>dpdpward init</code>.</p>{{end}}
<h2>Rule 6 security safeguards</h2>
<div class="scroll"><table><tr><th>Clause</th><th>Safeguard</th><th>Status</th><th>Evidence</th></tr>
{{range .R.Safeguards}}<tr><td class="nw">{{.Clause}}</td><td>{{.Title}}</td><td class="{{.Status}}">{{upper .Status}}</td><td>{{range .Evidence}}<code>{{.}}</code><br>{{end}}{{range .Checks}}{{.Status}}: <code>{{.Resource}}</code> — {{.Detail}}<br>{{end}}</td></tr>{{end}}
</table></div>
<h2>Findings</h2>
{{if .R.Findings}}<div class="scroll"><table><tr><th>Severity</th><th>Rule</th><th>Where</th><th>Finding</th></tr>
{{range .R.Findings}}<tr><td class="badge nw {{.SeverityStr}}">{{.SeverityStr}}</td><td class="nw"><code>{{.RuleID}}</code></td><td><code>{{.File}}{{if .Line}}:{{.Line}}{{end}}</code></td><td>{{.Message}}</td></tr>{{end}}
</table></div>{{else}}<p>No findings.</p>{{end}}
<h2>Record of Processing Activities</h2>
{{range .R.ROPA}}<h3>{{.ID}}</h3><div class="scroll"><table>
<tr><th>Description</th><td>{{.Description}}</td></tr>
<tr><th>Lawful basis</th><td>{{.Basis}}{{if .LegitimateUse}} ({{.LegitimateUse}}){{end}}</td></tr>
<tr><th>Data Principals</th><td>{{join .DataPrincipals ", "}}</td></tr>
<tr><th>Personal data</th><td>{{join .Categories ", "}}</td></tr>
<tr><th>Stores</th><td>{{join .Stores ", "}}</td></tr>
<tr><th>Retention</th><td>{{.Retention}}</td></tr>
<tr><th>Processors</th><td>{{join .Processors ", "}}</td></tr>
<tr><th>Transfers outside India</th><td>{{join .Transfers ", "}}</td></tr>
</table></div>{{else}}<p>No purposes declared.</p>{{end}}
{{if .R.Unmapped}}<p class="note"><b>Personal data without a declared purpose:</b> {{range .R.Unmapped}}<code>{{.}}</code> {{end}}</p>{{end}}
<h2>Data map</h2>
{{range .Stores}}<h3><code>{{.Name}}</code> <span class="meta">{{.Kind}} · {{.File}}</span></h3><div class="scroll"><table><tr><th>Field</th><th>Category</th><th>Sensitivity</th><th>Line</th></tr>
{{range .Elements}}<tr><td><code>{{.Field}}</code></td><td>{{.Label}}</td><td class="{{if eq .Sensitivity "high"}}high{{else if eq .Sensitivity "medium"}}medium{{else}}low{{end}}">{{.Sensitivity}}</td><td>{{.Line}}</td></tr>{{end}}
</table></div>{{else}}<p>No personal data fields found.</p>{{end}}
{{if .R.Values}}<h2>Identifier values found in files</h2><div class="scroll"><table><tr><th>File</th><th>Line</th><th>Kind</th><th>Value (redacted)</th></tr>
{{range .R.Values}}<tr><td><code>{{.File}}</code></td><td>{{.Line}}</td><td>{{.Kind}}</td><td><code>{{.Redacted}}</code></td></tr>{{end}}</table></div>{{end}}
<p class="meta">{{.Disclaimer}}</p>
</main></body></html>
`))
