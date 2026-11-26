resource "aws_db_instance" "app" {
  engine                  = "postgres"
  instance_class          = "db.t4g.medium"
  storage_encrypted       = false
  backup_retention_period = 7
}

resource "aws_s3_bucket" "kyc" {
  bucket = "example-lending-kyc"
}

resource "aws_s3_bucket_public_access_block" "kyc" {
  bucket                  = aws_s3_bucket.kyc.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_cloudtrail" "org" {
  name           = "org-trail"
  s3_bucket_name = "example-lending-trail"
}

resource "aws_cloudwatch_log_group" "api" {
  name              = "/example/api"
  retention_in_days = 90
}
