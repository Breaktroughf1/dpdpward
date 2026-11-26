// Package iac reads Terraform configuration (without running Terraform or
// fetching providers) and checks the settings that evidence DPDP Rules 2025
// Rule 6 security safeguards: encryption at rest, public exposure, audit
// logging, backups and one-year log retention.
package iac

import (
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
)

// Block is a Terraform block with its attributes and nested blocks.
type Block struct {
	Type   string            // resource type, e.g. aws_db_instance
	Name   string            // resource name
	File   string            // relative path
	Line   int               // line of the block header
	Attrs  map[string]string // raw attribute expressions at this level
	Blocks []*Block          // nested blocks (Type holds the block name)
}

var (
	resourceRe = regexp.MustCompile(`^\s*resource\s+"([\w-]+)"\s+"([\w-]+)"\s*\{\s*$`)
	nestedRe   = regexp.MustCompile(`^\s*([\w-]+)\s*\{\s*$`)
	attrRe     = regexp.MustCompile(`^\s*([\w-]+)\s*=\s*(.+?)\s*$`)
)

// Parse reads every *.tf file under root.
func Parse(root string, skip func(rel string) bool) ([]*Block, error) {
	var out []*Block
	err := filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return nil
		}
		rel, _ := filepath.Rel(root, p)
		rel = filepath.ToSlash(rel)
		if d.IsDir() {
			n := d.Name()
			if p != root && (n == ".git" || n == ".terraform" || n == "node_modules" || skip(rel)) {
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(p, ".tf") || skip(rel) {
			return nil
		}
		data, err := os.ReadFile(p)
		if err != nil {
			return nil
		}
		out = append(out, ParseFile(rel, string(data))...)
		return nil
	})
	return out, err
}

// ParseFile parses one Terraform file's resource blocks. Heredocs and
// expressions spanning lines are skipped, not misread.
func ParseFile(rel, src string) []*Block {
	ls := strings.Split(src, "\n")
	var out []*Block
	for i := 0; i < len(ls); i++ {
		m := resourceRe.FindStringSubmatch(stripComment(ls[i]))
		if m == nil {
			continue
		}
		b := &Block{Type: m[1], Name: m[2], File: rel, Line: i + 1, Attrs: map[string]string{}}
		i = parseBody(ls, i+1, b)
		out = append(out, b)
	}
	return out
}

// parseBody fills b from lines[start:] until its closing brace and returns
// the index of that brace.
func parseBody(ls []string, start int, b *Block) int {
	for i := start; i < len(ls); i++ {
		l := stripComment(ls[i])
		t := strings.TrimSpace(l)
		switch {
		case t == "}":
			return i
		case strings.HasPrefix(t, "#") || t == "":
			continue
		}
		if m := nestedRe.FindStringSubmatch(l); m != nil {
			nb := &Block{Type: m[1], File: b.File, Line: i + 1, Attrs: map[string]string{}}
			i = parseBody(ls, i+1, nb)
			b.Blocks = append(b.Blocks, nb)
			continue
		}
		if m := attrRe.FindStringSubmatch(l); m != nil {
			v := m[2]
			// Skip multi-line values (heredocs, lists, maps, function calls).
			if strings.HasPrefix(v, "<<") {
				i = skipHeredoc(ls, i, strings.TrimLeft(strings.TrimPrefix(v, "<<"), "-~"))
				continue
			}
			open := strings.Count(v, "[") + strings.Count(v, "{") + strings.Count(v, "(")
			closeN := strings.Count(v, "]") + strings.Count(v, "}") + strings.Count(v, ")")
			for open > closeN && i+1 < len(ls) {
				i++
				v += " " + strings.TrimSpace(stripComment(ls[i]))
				open = strings.Count(v, "[") + strings.Count(v, "{") + strings.Count(v, "(")
				closeN = strings.Count(v, "]") + strings.Count(v, "}") + strings.Count(v, ")")
			}
			b.Attrs[m[1]] = v
		}
	}
	return len(ls)
}

func skipHeredoc(ls []string, i int, marker string) int {
	for j := i + 1; j < len(ls); j++ {
		if strings.TrimSpace(ls[j]) == marker {
			return j
		}
	}
	return len(ls)
}

func stripComment(l string) string {
	inStr := false
	for i := 0; i < len(l); i++ {
		switch {
		case l[i] == '"' && (i == 0 || l[i-1] != '\\'):
			inStr = !inStr
		case !inStr && l[i] == '#':
			return l[:i]
		case !inStr && l[i] == '/' && i+1 < len(l) && l[i+1] == '/':
			return l[:i]
		}
	}
	return l
}

// Check is one safeguard observation from IaC.
type Check struct {
	Safeguard string `json:"safeguard"` // encryption | access_control | logging | backups | log_retention
	Status    string `json:"status"`    // pass | fail | unknown
	Resource  string `json:"resource"`  // type.name
	File      string `json:"file"`
	Line      int    `json:"line"`
	Detail    string `json:"detail"`
}

func (b *Block) attr(k string) (string, bool) {
	v, ok := b.Attrs[k]
	return strings.Trim(v, `"`), ok
}

func (b *Block) nested(name string) []*Block {
	var out []*Block
	for _, n := range b.Blocks {
		if n.Type == name {
			out = append(out, n)
		}
	}
	return out
}

func (b *Block) id() string { return b.Type + "." + b.Name }

var dbPorts = map[int]bool{1433: true, 1521: true, 3306: true, 5432: true, 6379: true, 9042: true, 9200: true, 27017: true}

// Evaluate derives safeguard checks from parsed resources.
func Evaluate(blocks []*Block) []Check {
	var out []Check
	add := func(sg, status string, b *Block, detail string) {
		out = append(out, Check{Safeguard: sg, Status: status, Resource: b.id(), File: b.File, Line: b.Line, Detail: detail})
	}
	ebsDefault := false
	s3Encrypted := map[string]bool{}
	s3Blocked := map[string]bool{}
	for _, b := range blocks {
		switch b.Type {
		case "aws_ebs_encryption_by_default":
			if v, _ := b.attr("enabled"); v != "false" {
				ebsDefault = true
			}
		case "aws_s3_bucket_server_side_encryption_configuration":
			if v, ok := b.attr("bucket"); ok {
				s3Encrypted[refName(v)] = true
			}
		case "aws_s3_bucket_public_access_block":
			all := true
			for _, k := range []string{"block_public_acls", "block_public_policy", "ignore_public_acls", "restrict_public_buckets"} {
				if v, _ := b.attr(k); v != "true" {
					all = false
				}
			}
			if v, ok := b.attr("bucket"); ok {
				s3Blocked[refName(v)] = all
			}
			if all {
				add("access_control", "pass", b, "all four S3 public-access blocks are on")
			} else {
				add("access_control", "fail", b, "S3 public access block does not enable all four settings")
			}
		}
	}
	for _, b := range blocks {
		switch b.Type {
		case "aws_db_instance", "aws_rds_cluster", "aws_docdb_cluster", "aws_neptune_cluster", "aws_redshift_cluster":
			key := "storage_encrypted"
			if b.Type == "aws_redshift_cluster" {
				key = "encrypted"
			}
			if v, ok := b.attr(key); ok && v == "true" {
				add("encryption", "pass", b, key+" = true")
			} else if ok && v != "false" {
				add("encryption", "unknown", b, key+" is set by an expression ("+v+"); check the resolved value")
			} else {
				add("encryption", "fail", b, key+" is not true; storage is unencrypted by default for this resource")
			}
			if v, _ := b.attr("publicly_accessible"); v == "true" {
				add("access_control", "fail", b, "publicly_accessible = true")
			}
			if b.Type == "aws_db_instance" || b.Type == "aws_rds_cluster" {
				v, ok := b.attr("backup_retention_period")
				n, err := strconv.Atoi(v)
				switch {
				case !ok:
					add("backups", "unknown", b, "backup_retention_period not set; confirm the provider default meets your recovery needs")
				case err != nil:
					add("backups", "unknown", b, "backup_retention_period set by an expression")
				case n == 0:
					add("backups", "fail", b, "backup_retention_period = 0 disables automated backups")
				default:
					add("backups", "pass", b, "automated backups kept for "+v+" day(s)")
				}
			}
		case "aws_ebs_volume":
			if v, _ := b.attr("encrypted"); v == "true" || ebsDefault {
				add("encryption", "pass", b, "EBS volume encrypted")
			} else {
				add("encryption", "fail", b, "EBS volume not encrypted and no aws_ebs_encryption_by_default")
			}
		case "aws_s3_bucket":
			// S3 applies SSE-S3 to new objects by default since January 2023.
			if s3Encrypted[b.Name] {
				add("encryption", "pass", b, "explicit server-side encryption configuration")
			} else {
				add("encryption", "pass", b, "S3 default encryption (SSE-S3) applies; consider SSE-KMS with your own key for personal data")
			}
			if blocked, ok := s3Blocked[b.Name]; !ok {
				add("access_control", "unknown", b, "no aws_s3_bucket_public_access_block for this bucket (an account-level block may apply)")
			} else if !blocked {
				add("access_control", "fail", b, "bucket public access block is incomplete")
			}
			if acl, _ := b.attr("acl"); strings.HasPrefix(acl, "public") {
				add("access_control", "fail", b, "acl = "+acl)
			}
		case "aws_dynamodb_table":
			add("encryption", "pass", b, "DynamoDB encrypts at rest by default")
			pitr := false
			for _, n := range b.nested("point_in_time_recovery") {
				if v, _ := n.attr("enabled"); v == "true" {
					pitr = true
				}
			}
			if pitr {
				add("backups", "pass", b, "point-in-time recovery enabled")
			} else {
				add("backups", "fail", b, "point_in_time_recovery not enabled")
			}
		case "aws_security_group", "aws_security_group_rule", "aws_vpc_security_group_ingress_rule":
			rules := b.nested("ingress")
			if b.Type != "aws_security_group" {
				if v, _ := b.attr("type"); b.Type == "aws_vpc_security_group_ingress_rule" || v == "ingress" {
					rules = []*Block{b}
				}
			}
			for _, r := range rules {
				cidr := r.Attrs["cidr_blocks"] + r.Attrs["cidr_ipv4"] + r.Attrs["ipv6_cidr_blocks"] + r.Attrs["cidr_ipv6"]
				if !strings.Contains(cidr, "0.0.0.0/0") && !strings.Contains(cidr, "::/0") {
					continue
				}
				from, _ := strconv.Atoi(strings.Trim(r.Attrs["from_port"], `"`))
				to, _ := strconv.Atoi(strings.Trim(r.Attrs["to_port"], `"`))
				for p := range dbPorts {
					if p >= from && p <= to {
						add("access_control", "fail", b, "database port "+strconv.Itoa(p)+" open to the internet")
						break
					}
				}
			}
		case "aws_cloudtrail":
			add("logging", "pass", b, "CloudTrail records API activity")
		case "aws_cloudwatch_log_group":
			v, ok := b.attr("retention_in_days")
			n, err := strconv.Atoi(v)
			switch {
			case !ok || n == 0:
				add("log_retention", "pass", b, "log group never expires")
			case err != nil:
				add("log_retention", "unknown", b, "retention_in_days set by an expression")
			case n < 365:
				add("log_retention", "fail", b, "retention_in_days = "+v+"; Rule 6 expects logs kept for at least one year")
			default:
				add("log_retention", "pass", b, "logs kept for "+v+" days")
			}
		case "google_sql_database_instance":
			add("encryption", "pass", b, "Cloud SQL encrypts at rest by default")
			for _, s := range b.nested("settings") {
				for _, bc := range s.nested("backup_configuration") {
					if v, _ := bc.attr("enabled"); v == "true" {
						add("backups", "pass", b, "backups enabled")
					} else {
						add("backups", "fail", b, "backup_configuration.enabled is not true")
					}
				}
				for _, ip := range s.nested("ip_configuration") {
					for _, an := range ip.nested("authorized_networks") {
						if v, _ := an.attr("value"); v == "0.0.0.0/0" {
							add("access_control", "fail", b, "authorized network 0.0.0.0/0")
						}
					}
				}
			}
		case "azurerm_storage_account":
			if v, _ := b.attr("allow_nested_items_to_be_public"); v == "true" {
				add("access_control", "fail", b, "allow_nested_items_to_be_public = true")
			}
			add("encryption", "pass", b, "Azure Storage encrypts at rest by default")
		case "azurerm_mssql_server", "azurerm_postgresql_flexible_server", "azurerm_mysql_flexible_server":
			if v, _ := b.attr("public_network_access_enabled"); v == "true" {
				add("access_control", "fail", b, "public_network_access_enabled = true")
			}
		}
	}
	sort.SliceStable(out, func(i, j int) bool {
		if out[i].Safeguard != out[j].Safeguard {
			return out[i].Safeguard < out[j].Safeguard
		}
		return out[i].Resource < out[j].Resource
	})
	return out
}

// refName extracts NAME from aws_s3_bucket.NAME.id style references.
func refName(v string) string {
	parts := strings.Split(strings.Trim(v, `"${}`), ".")
	if len(parts) >= 2 {
		return parts[1]
	}
	return v
}
