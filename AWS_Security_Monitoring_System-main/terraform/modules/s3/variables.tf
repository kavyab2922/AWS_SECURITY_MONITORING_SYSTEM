variable "logs_bucket_name" {
  description = "Name of the S3 bucket for storing security logs"
  type        = string
}

variable "environment" {
  description = "Deployment environment (dev, staging, prod)"
  type        = string
  default     = "dev"
}
