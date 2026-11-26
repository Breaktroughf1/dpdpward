package classify

import (
	"bufio"
	"bytes"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	"github.com/Breaktroughf1/dpdpward/internal/model"
)

// Identifier-like values committed to a repository (fixtures, seeds, logs,
// configs) are personal data too. Detection favours precision: Aadhaar
// numbers must pass the Verhoeff check, GSTINs their check character, and
// UPI IDs must use a known payment-app handle.

var (
	aadhaarRe = regexp.MustCompile(`\b[2-9][0-9]{3}[ -]?[0-9]{4}[ -]?[0-9]{4}\b`)
	// PAN: 4th character is the holder type; P = individual.
	panRe   = regexp.MustCompile(`\b[A-Z]{3}[ABCFGHJLPT][A-Z][0-9]{4}[A-Z]\b`)
	gstinRe = regexp.MustCompile(`\b[0-3][0-9][A-Z]{5}[0-9]{4}[A-Z][1-9A-Z]Z[0-9A-Z]\b`)
	upiRe   = regexp.MustCompile(`\b[a-zA-Z0-9.\-_]{2,64}@(ybl|okaxis|okhdfcbank|okicici|oksbi|paytm|upi|apl|ibl|axl|icici|sbi|hdfcbank|axisbank|kotak|fbl|yesbank|ptyes|ptaxis|pthdfc|ptsbi|waicici|wahdfcbank|waaxis|wasbi|freecharge|jupiteraxis|slc|idfcbank|pnb|boi|barodampay|aubank|rbl|federal|indus|uco|unionbank|cnrb|kbl|airtel|jio)\b`)
)

var verhoeffD = [10][10]int{
	{0, 1, 2, 3, 4, 5, 6, 7, 8, 9}, {1, 2, 3, 4, 0, 6, 7, 8, 9, 5}, {2, 3, 4, 0, 1, 7, 8, 9, 5, 6},
	{3, 4, 0, 1, 2, 8, 9, 5, 6, 7}, {4, 0, 1, 2, 3, 9, 5, 6, 7, 8}, {5, 9, 8, 7, 6, 0, 4, 3, 2, 1},
	{6, 5, 9, 8, 7, 1, 0, 4, 3, 2}, {7, 6, 5, 9, 8, 2, 1, 0, 4, 3}, {8, 7, 6, 5, 9, 3, 2, 1, 0, 4},
	{9, 8, 7, 6, 5, 4, 3, 2, 1, 0},
}
var verhoeffP = [8][10]int{
	{0, 1, 2, 3, 4, 5, 6, 7, 8, 9}, {1, 5, 7, 6, 2, 8, 3, 0, 9, 4}, {5, 8, 0, 3, 7, 9, 6, 1, 4, 2},
	{8, 9, 1, 6, 0, 4, 3, 5, 2, 7}, {9, 4, 5, 3, 1, 2, 6, 8, 7, 0}, {4, 2, 8, 6, 5, 7, 3, 9, 0, 1},
	{2, 7, 9, 3, 8, 0, 6, 4, 1, 5}, {7, 0, 4, 6, 9, 1, 3, 2, 5, 8},
}
var verhoeffInv = [10]int{0, 4, 3, 2, 1, 5, 6, 7, 8, 9}

// VerhoeffValid reports whether a digit string carries a valid Verhoeff
// check digit (as Aadhaar numbers do).
func VerhoeffValid(digits string) bool {
	c := 0
	for i := 0; i < len(digits); i++ {
		d := digits[len(digits)-1-i]
		if d < '0' || d > '9' {
			return false
		}
		c = verhoeffD[c][verhoeffP[i%8][d-'0']]
	}
	return c == 0
}

// VerhoeffDigit returns the check digit to append to digits.
func VerhoeffDigit(digits string) byte {
	c := 0
	for i := 0; i < len(digits); i++ {
		d := digits[len(digits)-1-i]
		c = verhoeffD[c][verhoeffP[(i+1)%8][d-'0']]
	}
	return byte('0' + verhoeffInv[c])
}

const gstChars = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ"

// GSTINCheck returns the check character for the first 14 characters.
func GSTINCheck(first14 string) byte {
	sum := 0
	for i := 0; i < 14; i++ {
		v := strings.IndexByte(gstChars, first14[i])
		if v < 0 {
			return 0
		}
		f := 1
		if i%2 == 1 {
			f = 2
		}
		p := v * f
		sum += p/36 + p%36
	}
	return gstChars[(36-sum%36)%36]
}

// GSTINValid reports whether a 15-character GSTIN has a valid check character.
func GSTINValid(g string) bool {
	return len(g) == 15 && GSTINCheck(g[:14]) == g[14]
}

func redact(s string) string {
	if len(s) <= 4 {
		return strings.Repeat("•", len(s))
	}
	return strings.Repeat("•", len(s)-4) + s[len(s)-4:]
}

// textExt lists file types scanned for identifier values.
var textExt = map[string]bool{".sql": true, ".csv": true, ".tsv": true, ".json": true, ".jsonl": true, ".ndjson": true,
	".yaml": true, ".yml": true, ".xml": true, ".py": true, ".js": true, ".ts": true, ".go": true, ".java": true,
	".kt": true, ".rb": true, ".php": true, ".txt": true, ".log": true, ".env": true, ".properties": true,
	".ini": true, ".toml": true, ".md": true, ".html": true, ".dart": true, ".cs": true, ".swift": true}

var skipDirs = map[string]bool{".git": true, "node_modules": true, "vendor": true, "dist": true, "build": true,
	".venv": true, "venv": true, "__pycache__": true, "target": true, ".terraform": true, ".next": true}

// Values scans text files under root for identifier-like values.
func Values(root string, exclude []string, matchExcluded func(string, []string) bool) ([]model.ValueHit, error) {
	var out []model.ValueHit
	err := filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return nil
		}
		rel, _ := filepath.Rel(root, p)
		rel = filepath.ToSlash(rel)
		if d.IsDir() {
			if p != root && (skipDirs[d.Name()] || matchExcluded(rel, exclude)) {
				return filepath.SkipDir
			}
			return nil
		}
		ext := strings.ToLower(filepath.Ext(rel))
		if !textExt[ext] && !strings.HasPrefix(filepath.Base(rel), ".env") {
			return nil
		}
		if matchExcluded(rel, exclude) {
			return nil
		}
		info, err := d.Info()
		if err != nil || info.Size() > 2<<20 {
			return nil
		}
		data, err := os.ReadFile(p)
		if err != nil || bytes.IndexByte(data, 0) >= 0 {
			return nil
		}
		out = append(out, ScanText(rel, data)...)
		return nil
	})
	sort.SliceStable(out, func(i, j int) bool {
		if out[i].File != out[j].File {
			return out[i].File < out[j].File
		}
		return out[i].Line < out[j].Line
	})
	return out, err
}

// ScanText finds identifier-like values in one file's contents.
func ScanText(rel string, data []byte) []model.ValueHit {
	var out []model.ValueHit
	sc := bufio.NewScanner(bytes.NewReader(data))
	sc.Buffer(make([]byte, 64*1024), 2<<20)
	for n := 1; sc.Scan(); n++ {
		line := sc.Text()
		for _, m := range aadhaarRe.FindAllString(line, -1) {
			digits := strings.NewReplacer(" ", "", "-", "").Replace(m)
			if VerhoeffValid(digits) && !repetitive(digits) {
				out = append(out, model.ValueHit{File: rel, Line: n, Kind: "aadhaar", Redacted: redact(digits), Checksum: true})
			}
		}
		for _, m := range gstinRe.FindAllString(line, -1) {
			if GSTINValid(m) {
				out = append(out, model.ValueHit{File: rel, Line: n, Kind: "gstin", Redacted: redact(m), Checksum: true})
			}
		}
		for _, m := range panRe.FindAllString(line, -1) {
			if !insideGSTIN(line, m) {
				out = append(out, model.ValueHit{File: rel, Line: n, Kind: "pan", Redacted: redact(m)})
			}
		}
		for _, m := range upiRe.FindAllString(line, -1) {
			out = append(out, model.ValueHit{File: rel, Line: n, Kind: "upi", Redacted: redact(m)})
		}
	}
	return out
}

// insideGSTIN reports whether pan only appears as part of a GSTIN (whose
// characters 3-12 are a PAN) on this line.
func insideGSTIN(line, pan string) bool {
	for _, g := range gstinRe.FindAllString(line, -1) {
		if g[2:12] == pan {
			return true
		}
	}
	return false
}

// repetitive rejects obvious placeholders such as 2222 2222 2222.
func repetitive(d string) bool {
	return strings.Count(d, d[:1]) == len(d) || d == "234567890123"[:len(d)]
}
