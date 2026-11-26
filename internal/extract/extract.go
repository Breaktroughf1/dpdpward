// Package extract finds data stores and their fields in source trees without
// executing or importing anything: SQL DDL, Prisma, Django, SQLAlchemy,
// TypeORM, Mongoose, Rails schema.rb, JPA/Hibernate entities and Go structs
// with persistence tags. Parsers are deliberately tolerant line scanners; a
// file they do not understand yields nothing rather than an error.
package extract

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

// Result is everything found under a root.
type Result struct {
	Stores  []model.Store `json:"stores"`
	Files   int           `json:"files_scanned"`
	Skipped []string      `json:"skipped,omitempty"`
}

// MaxFileSize bounds the files read (bytes).
const MaxFileSize = 2 << 20

var skipDirs = map[string]bool{".git": true, "node_modules": true, "vendor": true, "dist": true, "build": true,
	".venv": true, "venv": true, "__pycache__": true, "target": true, ".terraform": true, ".next": true}

// Walk extracts stores from every recognised file under root. Paths in the
// result are relative to root and use forward slashes.
func Walk(root string, exclude []string) (Result, error) {
	var res Result
	err := filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			res.Skipped = append(res.Skipped, p+": "+err.Error())
			return nil
		}
		rel, _ := filepath.Rel(root, p)
		rel = filepath.ToSlash(rel)
		if d.IsDir() {
			if p != root && (skipDirs[d.Name()] || excluded(rel, exclude)) {
				return filepath.SkipDir
			}
			return nil
		}
		if excluded(rel, exclude) || !d.Type().IsRegular() {
			return nil
		}
		parse := parserFor(rel)
		if parse == nil {
			return nil
		}
		info, err := d.Info()
		if err != nil || info.Size() > MaxFileSize {
			res.Skipped = append(res.Skipped, rel+": too large or unreadable")
			return nil
		}
		data, err := os.ReadFile(p)
		if err != nil {
			res.Skipped = append(res.Skipped, rel+": "+err.Error())
			return nil
		}
		res.Files++
		for _, s := range parse(data) {
			s.File = rel
			res.Stores = append(res.Stores, s)
		}
		return nil
	})
	sort.SliceStable(res.Stores, func(i, j int) bool {
		if res.Stores[i].File != res.Stores[j].File {
			return res.Stores[i].File < res.Stores[j].File
		}
		return res.Stores[i].Line < res.Stores[j].Line
	})
	return res, err
}

func excluded(rel string, patterns []string) bool {
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

type parser func([]byte) []model.Store

func parserFor(rel string) parser {
	base := strings.ToLower(filepath.Base(rel))
	ext := strings.ToLower(filepath.Ext(rel))
	switch {
	case ext == ".sql":
		return SQL
	case ext == ".prisma":
		return Prisma
	case base == "schema.rb" || (ext == ".rb" && strings.Contains(rel, "db/migrate/")):
		return Rails
	case ext == ".py":
		return Python
	case ext == ".ts" || ext == ".js" || ext == ".mjs" || ext == ".cjs":
		return JS
	case ext == ".java" || ext == ".kt":
		return JPA
	case ext == ".go":
		return Go
	}
	return nil
}

// lines returns the file split into lines (without terminators).
func lines(data []byte) []string {
	var out []string
	sc := bufio.NewScanner(bytes.NewReader(data))
	sc.Buffer(make([]byte, 64*1024), MaxFileSize)
	for sc.Scan() {
		out = append(out, sc.Text())
	}
	return out
}

func unquote(s string) string {
	return strings.Trim(s, "`\"'[] ")
}

// ---------------------------------------------------------------- SQL DDL

var (
	createTableRe = regexp.MustCompile(`(?i)^\s*create\s+(?:temporary\s+|temp\s+|unlogged\s+)?table\s+(?:if\s+not\s+exists\s+)?([` + "`" + `"\[\]\w.]+)\s*\(?`)
	sqlColRe      = regexp.MustCompile(`^\s*([` + "`" + `"\[]?[A-Za-z_][\w]*[` + "`" + `"\]]?)\s+([A-Za-z][\w]*(?:\s*\([^)]*\))?)`)
	sqlNotColRe   = regexp.MustCompile(`(?i)^\s*(constraint|primary|foreign|unique|key|index|check|exclude|fulltext|spatial|period|like)\b`)
	alterAddRe    = regexp.MustCompile(`(?i)^\s*alter\s+table\s+(?:if\s+exists\s+)?(?:only\s+)?([` + "`" + `"\[\]\w.]+)\s+add\s+(?:column\s+)?(?:if\s+not\s+exists\s+)?([` + "`" + `"\[]?[A-Za-z_]\w*[` + "`" + `"\]]?)\s+([A-Za-z]\w*)`)
)

// SQL parses CREATE TABLE and ALTER TABLE ... ADD COLUMN statements.
func SQL(data []byte) []model.Store {
	ls := lines(data)
	var out []model.Store
	idx := map[string]int{}
	for i := 0; i < len(ls); i++ {
		if m := alterAddRe.FindStringSubmatch(ls[i]); m != nil {
			name := tableName(m[1])
			k, ok := idx[strings.ToLower(name)]
			if !ok {
				out = append(out, model.Store{Name: name, Kind: "sql-table", Line: i + 1})
				k = len(out) - 1
				idx[strings.ToLower(name)] = k
			}
			out[k].Fields = append(out[k].Fields, model.Field{Name: unquote(m[2]), Type: strings.ToLower(m[3]), Line: i + 1})
			continue
		}
		m := createTableRe.FindStringSubmatch(ls[i])
		if m == nil {
			continue
		}
		st := model.Store{Name: tableName(m[1]), Kind: "sql-table", Line: i + 1}
		depth := strings.Count(ls[i], "(") - strings.Count(ls[i], ")")
		// Columns declared on the same line after "(".
		rest := ""
		if j := strings.Index(ls[i], "("); j >= 0 {
			rest = ls[i][j+1:]
		}
		body := []struct {
			text string
			line int
		}{{rest, i + 1}}
		for j := i + 1; j < len(ls) && depth > 0; j++ {
			body = append(body, struct {
				text string
				line int
			}{ls[j], j + 1})
			depth += strings.Count(ls[j], "(") - strings.Count(ls[j], ")")
			i = j
		}
		for _, b := range body {
			for _, part := range strings.Split(b.text, ",") {
				part = strings.TrimSpace(strings.SplitN(part, "--", 2)[0])
				if part == "" || sqlNotColRe.MatchString(part) {
					continue
				}
				cm := sqlColRe.FindStringSubmatch(part)
				if cm == nil {
					continue
				}
				typ := strings.ToLower(strings.Fields(cm[2])[0])
				if typ == "as" || typ == "select" {
					continue
				}
				st.Fields = append(st.Fields, model.Field{Name: unquote(cm[1]), Type: typ, Line: b.line})
			}
		}
		if len(st.Fields) > 0 {
			if k, ok := idx[strings.ToLower(st.Name)]; ok {
				out[k].Fields = append(out[k].Fields, st.Fields...)
			} else {
				idx[strings.ToLower(st.Name)] = len(out)
				out = append(out, st)
			}
		}
	}
	return out
}

func tableName(s string) string {
	s = unquote(s)
	if i := strings.LastIndexByte(s, '.'); i >= 0 {
		s = unquote(s[i+1:])
	}
	return s
}

// ----------------------------------------------------------------- Prisma

var (
	prismaModelRe = regexp.MustCompile(`^\s*model\s+(\w+)\s*\{`)
	prismaFieldRe = regexp.MustCompile(`^\s*(\w+)\s+([A-Za-z]\w*)(\[\])?\??`)
	prismaMapRe   = regexp.MustCompile(`@@map\(\s*"([^"]+)"`)
)

// Prisma parses `model X { ... }` blocks.
func Prisma(data []byte) []model.Store {
	ls := lines(data)
	var out []model.Store
	for i := 0; i < len(ls); i++ {
		m := prismaModelRe.FindStringSubmatch(ls[i])
		if m == nil {
			continue
		}
		st := model.Store{Name: m[1], Kind: "prisma-model", Line: i + 1}
		for j := i + 1; j < len(ls); j++ {
			l := strings.TrimSpace(ls[j])
			if strings.HasPrefix(l, "}") {
				i = j
				break
			}
			if mm := prismaMapRe.FindStringSubmatch(l); mm != nil {
				st.Name = mm[1]
				continue
			}
			if strings.HasPrefix(l, "//") || strings.HasPrefix(l, "@@") {
				continue
			}
			if fm := prismaFieldRe.FindStringSubmatch(l); fm != nil {
				st.Fields = append(st.Fields, model.Field{Name: fm[1], Type: fm[2], Line: j + 1})
			}
		}
		out = append(out, st)
	}
	return out
}

// ------------------------------------------------- Python: Django, SQLAlchemy

var (
	pyClassRe      = regexp.MustCompile(`^class\s+(\w+)\s*\(([^)]*)\)\s*:`)
	djangoFieldRe  = regexp.MustCompile(`^\s+(\w+)\s*=\s*(?:models\.)?(\w+Field|ForeignKey|OneToOneField|ManyToManyField)\s*\(`)
	saColumnRe     = regexp.MustCompile(`^\s+(\w+)\s*(?::\s*[^=]+)?=\s*(?:sa\.|db\.|sqlalchemy\.)?(?:Column|mapped_column)\s*\(\s*(?:(?:sa\.|db\.)?(\w+))?`)
	saTablenameRe  = regexp.MustCompile(`^\s+__tablename__\s*=\s*["']([^"']+)["']`)
	djangoDbTable  = regexp.MustCompile(`^\s+db_table\s*=\s*["']([^"']+)["']`)
	pydanticRe     = regexp.MustCompile(`^\s+(\w+)\s*:\s*([\w\[\]., |]+?)\s*(?:=|$)`)
	persistedBases = regexp.MustCompile(`(models\.Model|Model|Base|DeclarativeBase|db\.Model|SQLModel|Document)`)
)

// Python parses Django models, SQLAlchemy declarative models and SQLModel
// tables (classes whose bases look persisted).
func Python(data []byte) []model.Store {
	ls := lines(data)
	var out []model.Store
	for i := 0; i < len(ls); i++ {
		m := pyClassRe.FindStringSubmatch(ls[i])
		if m == nil || !persistedBases.MatchString(m[2]) {
			continue
		}
		sqlModel := strings.Contains(m[2], "SQLModel")
		if sqlModel && !strings.Contains(m[2], "table=True") {
			continue
		}
		kind := "django-model"
		if !strings.Contains(m[2], "models.Model") {
			kind = "sqlalchemy-model"
		}
		st := model.Store{Name: m[1], Kind: kind, Line: i + 1}
		for j := i + 1; j < len(ls); j++ {
			l := ls[j]
			if strings.TrimSpace(l) != "" && !strings.HasPrefix(l, " ") && !strings.HasPrefix(l, "\t") {
				i = j - 1
				break
			}
			if tm := saTablenameRe.FindStringSubmatch(l); tm != nil {
				st.Name = tm[1]
				continue
			}
			if tm := djangoDbTable.FindStringSubmatch(l); tm != nil {
				st.Name = tm[1]
				continue
			}
			if fm := djangoFieldRe.FindStringSubmatch(l); fm != nil {
				st.Fields = append(st.Fields, model.Field{Name: fm[1], Type: fm[2], Line: j + 1})
				continue
			}
			if fm := saColumnRe.FindStringSubmatch(l); fm != nil {
				st.Fields = append(st.Fields, model.Field{Name: fm[1], Type: fm[2], Line: j + 1})
				continue
			}
			if sqlModel {
				if fm := pydanticRe.FindStringSubmatch(l); fm != nil && !strings.HasPrefix(fm[1], "_") && fm[1] != "model_config" {
					st.Fields = append(st.Fields, model.Field{Name: fm[1], Type: strings.TrimSpace(fm[2]), Line: j + 1})
				}
			}
			if j == len(ls)-1 {
				i = j
			}
		}
		if len(st.Fields) > 0 {
			out = append(out, st)
		}
	}
	return out
}

// ----------------------------------------------- JS/TS: TypeORM, Mongoose

var (
	typeormEntityRe = regexp.MustCompile(`@Entity\(\s*(?:["']([^"']+)["']|\{[^}]*name\s*:\s*["']([^"']+)["'])?`)
	tsClassRe       = regexp.MustCompile(`class\s+(\w+)`)
	typeormColRe    = regexp.MustCompile(`@(?:Column|PrimaryGeneratedColumn|PrimaryColumn|CreateDateColumn|UpdateDateColumn)\b`)
	tsPropRe        = regexp.MustCompile(`^\s*(?:public\s+|private\s+|protected\s+|readonly\s+)*(\w+)\s*[!?]?\s*:\s*([\w\[\]<> |]+)`)
	mongooseRe      = regexp.MustCompile(`(?:new\s+(?:mongoose\.)?Schema|mongoose\.Schema)\s*(?:<[^>]*>)?\s*\(\s*\{`)
	mongooseModelRe = regexp.MustCompile(`model\s*(?:<[^>]*>)?\s*\(\s*["'](\w+)["']`)
	jsKeyRe         = regexp.MustCompile(`^\s*["']?(\w+)["']?\s*:\s*(\{|\[|[A-Za-z]\w*)`)
	constNameRe     = regexp.MustCompile(`(?:const|let|var)\s+(\w+)\s*=`)
)

// JS parses TypeORM entities and Mongoose schemas.
func JS(data []byte) []model.Store {
	ls := lines(data)
	var out []model.Store
	for i := 0; i < len(ls); i++ {
		if m := typeormEntityRe.FindStringSubmatch(ls[i]); m != nil {
			name := m[1] + m[2]
			st := model.Store{Kind: "typeorm-entity", Line: i + 1}
			depth := 0
			started := false
			pendingCol := false
			for j := i; j < len(ls); j++ {
				if st.Name == "" && name == "" {
					if cm := tsClassRe.FindStringSubmatch(ls[j]); cm != nil {
						st.Name = cm[1]
					}
				}
				if typeormColRe.MatchString(ls[j]) {
					pendingCol = true
				}
				if pendingCol && j > i {
					if pm := tsPropRe.FindStringSubmatch(ls[j]); pm != nil && !strings.Contains(ls[j], "@") {
						st.Fields = append(st.Fields, model.Field{Name: pm[1], Type: strings.TrimSpace(pm[2]), Line: j + 1})
						pendingCol = false
					}
				}
				depth += strings.Count(ls[j], "{") - strings.Count(ls[j], "}")
				if strings.Contains(ls[j], "{") {
					started = true
				}
				if started && depth <= 0 {
					i = j
					break
				}
			}
			if name != "" {
				st.Name = name
			}
			if len(st.Fields) > 0 {
				out = append(out, st)
			}
			continue
		}
		if mongooseRe.MatchString(ls[i]) {
			st := model.Store{Kind: "mongoose-schema", Line: i + 1}
			if cm := constNameRe.FindStringSubmatch(ls[i]); cm != nil {
				st.Name = strings.TrimSuffix(strings.TrimSuffix(cm[1], "Schema"), "schema")
			}
			depth := strings.Count(ls[i], "{") - strings.Count(ls[i], "}")
			for j := i + 1; j < len(ls) && depth > 0; j++ {
				if depth == 1 {
					if km := jsKeyRe.FindStringSubmatch(ls[j]); km != nil {
						st.Fields = append(st.Fields, model.Field{Name: km[1], Type: km[2], Line: j + 1})
					}
				}
				depth += strings.Count(ls[j], "{") - strings.Count(ls[j], "}")
				i = j
			}
			// Prefer the collection name from mongoose.model("Name", schema).
			for _, l := range ls {
				if mm := mongooseModelRe.FindStringSubmatch(l); mm != nil && strings.EqualFold(mm[1], st.Name) {
					st.Name = mm[1]
				}
			}
			if st.Name == "" {
				st.Name = "schema"
			}
			if len(st.Fields) > 0 {
				out = append(out, st)
			}
		}
	}
	return out
}

// ------------------------------------------------------------- Rails

var (
	railsTableRe = regexp.MustCompile(`create_table\s+[:"']?(\w+)["']?`)
	railsColRe   = regexp.MustCompile(`^\s*t\.(\w+)\s+[:"'](\w+)["']?`)
	railsAddRe   = regexp.MustCompile(`add_column\s+[:"'](\w+)["']?\s*,\s*[:"'](\w+)["']?\s*,\s*:(\w+)`)
)

// Rails parses db/schema.rb and migrations.
func Rails(data []byte) []model.Store {
	ls := lines(data)
	var out []model.Store
	for i := 0; i < len(ls); i++ {
		if m := railsAddRe.FindStringSubmatch(ls[i]); m != nil {
			out = append(out, model.Store{Name: m[1], Kind: "rails-table", Line: i + 1,
				Fields: []model.Field{{Name: m[2], Type: m[3], Line: i + 1}}})
			continue
		}
		m := railsTableRe.FindStringSubmatch(ls[i])
		if m == nil {
			continue
		}
		st := model.Store{Name: m[1], Kind: "rails-table", Line: i + 1}
		for j := i + 1; j < len(ls); j++ {
			if strings.TrimSpace(ls[j]) == "end" {
				i = j
				break
			}
			if cm := railsColRe.FindStringSubmatch(ls[j]); cm != nil && cm[1] != "index" && cm[1] != "timestamps" {
				st.Fields = append(st.Fields, model.Field{Name: cm[2], Type: cm[1], Line: j + 1})
			}
		}
		out = append(out, st)
	}
	return out
}

// --------------------------------------------------------- Java/Kotlin JPA

var (
	jpaEntityRe = regexp.MustCompile(`@(?:Entity|Document|Table)\b`)
	jpaTableRe  = regexp.MustCompile(`@Table\s*\(\s*(?:name\s*=\s*)?"([^"]+)"`)
	jpaClassRe  = regexp.MustCompile(`(?:class|record)\s+(\w+)`)
	javaFieldRe = regexp.MustCompile(`^\s*(?:private|protected|public)?\s*(?:final\s+)?([A-Z][\w<>,\s]*?)\s+(\w+)\s*(?:=[^;]*)?;`)
	ktFieldRe   = regexp.MustCompile(`^\s*(?:val|var)\s+(\w+)\s*:\s*([\w<>?, ]+)`)
)

// JPA parses JPA/Hibernate (and Spring Data) entities in Java or Kotlin.
func JPA(data []byte) []model.Store {
	ls := lines(data)
	var out []model.Store
	for i := 0; i < len(ls); i++ {
		if !jpaEntityRe.MatchString(ls[i]) {
			continue
		}
		st := model.Store{Kind: "jpa-entity", Line: i + 1}
		table := ""
		depth := 0
		started := false
		for j := i; j < len(ls); j++ {
			if tm := jpaTableRe.FindStringSubmatch(ls[j]); tm != nil {
				table = tm[1]
			}
			if st.Name == "" {
				if cm := jpaClassRe.FindStringSubmatch(ls[j]); cm != nil {
					st.Name = cm[1]
				}
			}
			if started && depth == 1 && !strings.Contains(ls[j], "(") {
				if fm := javaFieldRe.FindStringSubmatch(ls[j]); fm != nil && !strings.Contains(ls[j], " static ") {
					st.Fields = append(st.Fields, model.Field{Name: fm[2], Type: strings.TrimSpace(fm[1]), Line: j + 1})
				} else if km := ktFieldRe.FindStringSubmatch(ls[j]); km != nil {
					st.Fields = append(st.Fields, model.Field{Name: km[1], Type: strings.TrimSpace(km[2]), Line: j + 1})
				}
			}
			// Kotlin data-class constructor parameters: `val x: T,`
			if st.Name != "" && !started {
				if km := ktFieldRe.FindStringSubmatch(ls[j]); km != nil {
					st.Fields = append(st.Fields, model.Field{Name: km[1], Type: strings.TrimSpace(km[2]), Line: j + 1})
				}
			}
			depth += strings.Count(ls[j], "{") - strings.Count(ls[j], "}")
			if strings.Contains(ls[j], "{") {
				started = true
			}
			if started && depth <= 0 {
				i = j
				break
			}
		}
		if table != "" {
			st.Name = table
		}
		if len(st.Fields) > 0 {
			out = append(out, st)
		}
	}
	return out
}

// ------------------------------------------------------------------- Go

var (
	goStructRe = regexp.MustCompile(`^type\s+(\w+)\s+struct\s*\{`)
	goFieldRe  = regexp.MustCompile("^\\s+(\\w+)\\s+([\\w.*\\[\\]]+)\\s*(`[^`]*`)?")
	goTagRe    = regexp.MustCompile(`(db|gorm|bson|dynamodbav|firestore|pg|sql)\s*:\s*"([^"]*)"`)
	gormColRe  = regexp.MustCompile(`column:(\w+)`)
	goTableRe  = regexp.MustCompile(`func\s*\(\s*(?:\w+\s+)?\*?(\w+)\s*\)\s*TableName\s*\(\s*\)\s*string\s*\{\s*return\s*"([^"]+)"`)
)

// Go parses structs whose fields carry persistence tags (db, gorm, bson, ...).
func Go(data []byte) []model.Store {
	ls := lines(data)
	tables := map[string]string{}
	for _, m := range goTableRe.FindAllStringSubmatch(string(data), -1) {
		tables[m[1]] = m[2]
	}
	var out []model.Store
	for i := 0; i < len(ls); i++ {
		m := goStructRe.FindStringSubmatch(ls[i])
		if m == nil {
			continue
		}
		st := model.Store{Name: m[1], Kind: "go-struct", Line: i + 1}
		if t, ok := tables[m[1]]; ok {
			st.Name = t
		}
		tagged := false
		for j := i + 1; j < len(ls); j++ {
			if strings.HasPrefix(strings.TrimSpace(ls[j]), "}") {
				i = j
				break
			}
			fm := goFieldRe.FindStringSubmatch(ls[j])
			if fm == nil {
				continue
			}
			name := fm[1]
			if tm := goTagRe.FindStringSubmatch(fm[3]); tm != nil {
				tagged = true
				col := strings.Split(tm[2], ",")[0]
				if tm[1] == "gorm" {
					col = ""
					if cm := gormColRe.FindStringSubmatch(tm[2]); cm != nil {
						col = cm[1]
					}
					if tm[2] == "-" {
						continue
					}
				}
				if col == "-" {
					continue
				}
				if col != "" {
					name = col
				}
			}
			st.Fields = append(st.Fields, model.Field{Name: name, Type: fm[2], Line: j + 1})
		}
		if tagged && len(st.Fields) > 0 {
			out = append(out, st)
		}
	}
	return out
}
