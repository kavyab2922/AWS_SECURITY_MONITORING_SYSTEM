resource "aws_s3_bucket" "logs_bucket" {
  bucket        = var.logs_bucket_name
  force_destroy = true

  tags = {
    Name        = var.logs_bucket_name
    Environment = var.environment
    Managed     = "Terraform"
  }
}

resource "aws_s3_bucket_ownership_controls" "logs_bucket" {
  bucket = aws_s3_bucket.logs_bucket.id
  rule {
    object_ownership = "BucketOwnerPreferred"
  }
}

resource "aws_s3_bucket_acl" "logs_bucket_acl" {
  depends_on = [aws_s3_bucket_ownership_controls.logs_bucket]
  bucket     = aws_s3_bucket.logs_bucket.id
  acl        = "private"
}

resource "aws_s3_bucket_versioning" "logs_bucket_versioning" {
  bucket = aws_s3_bucket.logs_bucket.id
  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "logs_bucket_encryption" {
  bucket = aws_s3_bucket.logs_bucket.id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"
    }
  }
}

resource "aws_s3_bucket_lifecycle_configuration" "logs_bucket_lifecycle" {
  bucket = aws_s3_bucket.logs_bucket.id

  rule {
    id     = "expire-old-logs"
    status = "Enabled"

    expiration {
      days = 90
    }

    transition {
      days          = 30
      storage_class = "STANDARD_IA"
    }
  }
}

# IAM policy for Lambda access to S3
resource "aws_iam_policy" "lambda_s3_access" {
  name        = "security-monitoring-lambda-s3-access"
  description = "IAM policy for S3 access from Lambda"

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = [
          "s3:GetObject",
          "s3:ListBucket",
          "s3:PutObject"
        ]
        Effect = "Allow"
        Resource = [
          "${aws_s3_bucket.logs_bucket.arn}",
          "${aws_s3_bucket.logs_bucket.arn}/*"
        ]
      }
    ]
  })
}

output "logs_bucket_name" {
  value = aws_s3_bucket.logs_bucket.id
}

output "logs_bucket_arn" {
  value = aws_s3_bucket.logs_bucket.arn
}

output "lambda_s3_access_policy_arn" {
  value = aws_iam_policy.lambda_s3_access.arn
}
