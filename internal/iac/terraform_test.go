package iac

import "testing"

const tf = `
resource "aws_db_instance" "main" {
  engine              = "postgres"
  storage_encrypted   = false   # oops
  publicly_accessible = true
  backup_retention_period = 0
  tags = {
    Name = "main"
  }
}

resource "aws_rds_cluster" "good" {
  storage_encrypted       = true
  backup_retention_period = 7
}

resource "aws_s3_bucket" "kyc" {
  bucket = "kyc-docs"
}

resource "aws_s3_bucket_public_access_block" "kyc" {
  bucket                  = aws_s3_bucket.kyc.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_security_group" "db" {
  ingress {
    from_port   = 5432
    to_port     = 5432
    cidr_blocks = [
      "0.0.0.0/0",
    ]
  }
}

resource "aws_cloudwatch_log_group" "app" {
  retention_in_days = 30
}

resource "aws_cloudtrail" "org" {
  name = "org"
  event_selector {
    read_write_type = "All"
  }
}

resource "aws_dynamodb_table" "sessions" {
  point_in_time_recovery {
    enabled = true
  }
  policy = <<EOF
{ "x": "}" }
EOF
}
`

func TestEvaluate(t *testing.T) {
	checks := Evaluate(ParseFile("main.tf", tf))
	type key struct{ sg, res, status string }
	got := map[key]bool{}
	for _, c := range checks {
		got[key{c.Safeguard, c.Resource, c.Status}] = true
	}
	want := []key{
		{"encryption", "aws_db_instance.main", "fail"},
		{"access_control", "aws_db_instance.main", "fail"},
		{"backups", "aws_db_instance.main", "fail"},
		{"encryption", "aws_rds_cluster.good", "pass"},
		{"backups", "aws_rds_cluster.good", "pass"},
		{"access_control", "aws_s3_bucket_public_access_block.kyc", "pass"},
		{"access_control", "aws_security_group.db", "fail"},
		{"log_retention", "aws_cloudwatch_log_group.app", "fail"},
		{"logging", "aws_cloudtrail.org", "pass"},
		{"backups", "aws_dynamodb_table.sessions", "pass"},
	}
	for _, w := range want {
		if !got[w] {
			t.Errorf("missing %+v in %+v", w, checks)
		}
	}
	if got[key{"access_control", "aws_s3_bucket.kyc", "unknown"}] {
		t.Error("bucket with a complete public access block must not be unknown")
	}
}

func FuzzParseFile(f *testing.F) {
	f.Add(tf)
	f.Fuzz(func(t *testing.T, s string) {
		_ = Evaluate(ParseFile("f.tf", s))
	})
}
