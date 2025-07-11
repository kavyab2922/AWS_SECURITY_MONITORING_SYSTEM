# Datadog AWS integration
resource "aws_iam_role" "datadog_integration" {
  name = "DatadogAWSIntegrationRole"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = "sts:AssumeRole"
        Effect = "Allow"
        Principal = {
          AWS = "arn:aws:iam::464622532012:root" # Datadog's account ID
        }
      }
    ]
  })
}

# IAM policy for Datadog integration
resource "aws_iam_role_policy" "datadog_integration" {
  name = "datadog-integration-policy"
  role = aws_iam_role.datadog_integration.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = [
          # "cloudtrail:DescribeTrails",
          # "cloudtrail:GetTrailStatus",
          # "cloudtrail:LookupEvents",
          "cloudwatch:Get*",
          "cloudwatch:List*",
          "ec2:Describe*",
          "ec2:Get*",
          "ecr:Describe*",
          "ecr:List*",
          "elasticloadbalancing:Describe*",
          "guardduty:Get*",
          "guardduty:List*",
          "iam:Get*",
          "iam:List*",
          "lambda:List*",
          "logs:Get*",
          "logs:Describe*",
          "logs:FilterLogEvents",
          "s3:GetBucketLogging",
          "s3:GetBucketLocation",
          "s3:GetBucketNotification",
          "s3:GetBucketTagging",
          "s3:ListAllMyBuckets",
          "s3:PutBucketNotification",
          "sns:List*",
          "tag:GetResources",
          "tag:GetTagKeys",
          "tag:GetTagValues",
          "wafv2:GetWebACL",
          "wafv2:ListWebACLs"
        ]
        Effect   = "Allow"
        Resource = "*"
      }
    ]
  })
}

# Get AWS account ID
data "aws_caller_identity" "current" {}

# Output the Datadog role ARN
output "datadog_role_arn" {
  description = "ARN of the IAM role for Datadog integration"
  value       = aws_iam_role.datadog_integration.arn
}
