variable "logs_bucket_name" {
  description = "S3 bucket name for security logs"
  type        = string
}

variable "datadog_api_key" {
  description = "Datadog API key for integration"
  type        = string
  sensitive   = true
}

variable "lambda_s3_policy_arn" {
  description = "ARN of the IAM policy for Lambda to access S3"
  type        = string
  default     = "arn:aws:iam::aws:policy/AmazonS3ReadOnlyAccess"
}
