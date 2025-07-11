resource "aws_inspector2_enabler" "main" {
  account_ids    = [data.aws_caller_identity.current.account_id]
  resource_types = ["EC2", "ECR", "LAMBDA"]
}

data "aws_caller_identity" "current" {}

/*
# Create an SNS topic for Inspector findings
resource "aws_sns_topic" "inspector_findings" {
  name = "inspector-findings-alerts"
}

# Create an EventBridge rule to capture Inspector findings
resource "aws_cloudwatch_event_rule" "inspector_findings" {
  name        = "inspector-findings-rule"
  description = "Capture Inspector findings"

  event_pattern = jsonencode({
    source      = ["aws.inspector2"]
    detail-type = ["Inspector2 Finding"]
  })
}

# Connect EventBridge rule to SNS topic
resource "aws_cloudwatch_event_target" "inspector_findings" {
  rule      = aws_cloudwatch_event_rule.inspector_findings.name
  target_id = "SendToSNS"
  arn       = aws_sns_topic.inspector_findings.arn
}
*/
