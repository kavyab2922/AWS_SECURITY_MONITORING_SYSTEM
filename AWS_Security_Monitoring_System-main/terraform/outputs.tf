output "datadog_role_arn" {
  description = "ARN of the IAM role for Datadog integration"
  value       = module.datadog.datadog_role_arn
}
