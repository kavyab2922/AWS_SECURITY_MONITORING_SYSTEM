# AWS Security Monitoring System

A comprehensive cloud security monitoring solution that integrates AWS security services with Datadog for enhanced visibility and analytics.

## Architecture Overview

This system utilizes a serverless architecture with AWS Lambda functions to collect and analyze security data from various AWS security services:

- **Collection Layer**: Lambda functions collect security findings from GuardDuty, Inspector, and WAF
- **Storage Layer**: S3 bucket stores collected security findings
- **Analysis Layer**: Security anomaly detection Lambda function processes findings
- **Integration Layer**: Datadog integration for real-time monitoring and alerting

## Components

- **AWS Security Services**:

  - Amazon GuardDuty for threat detection
  - Amazon Inspector for vulnerability assessment
  - AWS WAF for web application firewall protection

- **Lambda Functions**:

  - GuardDuty Collector
  - Inspector Collector
  - WAF Collector
  - Security Anomaly Detection

- **Storage**:

  - S3 bucket for storing security findings

- **Monitoring**:
  - Datadog integration for visualization and alerts

## Setup Instructions

### Prerequisites

- AWS Account
- Terraform installed
- Python 3.9+
- Datadog account (optional)

### Deployment

1. Clone this repository:

```
git clone [repository-url]
cd aws-security-monitoring
```

2. Configure AWS credentials:

```
aws configure
```

3. Update the terraform.tfvars file with your configuration:

```
cd terraform
cp terraform.tfvars.example terraform.tfvars
# Edit terraform.tfvars with your settings
```

4. Deploy the infrastructure:

```
terraform init
terraform apply
```

### Configuration

#### Datadog Integration (Optional)

To enable Datadog integration:

1. Obtain Datadog API and APP keys from your Datadog account
2. Add these keys to your terraform.tfvars file:

```
datadog_api_key = "your-datadog-api-key"
datadog_app_key = "your-datadog-app-key"
```

## Usage

After deployment, the system automatically collects security findings. To manually invoke the collection:

```
aws lambda invoke --function-name guardduty-collector output.json
aws lambda invoke --function-name inspector-collector output.json
aws lambda invoke --function-name waf-collector output.json
```

## Cleanup

To remove all resources:

```
cd terraform
terraform destroy
```

## License

MIT
