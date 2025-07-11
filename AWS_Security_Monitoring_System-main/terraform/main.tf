terraform {
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 4.0"
    }
    datadog = {
      source  = "datadog/datadog"
      version = "~> 3.0"
    }
  }
  required_version = ">= 1.0.0"
}

provider "aws" {
  region = var.aws_region
}

provider "datadog" {
  api_key = var.datadog_api_key
  app_key = var.datadog_app_key
}

# Create S3 bucket first
module "s3" {
  source           = "./modules/s3"
  logs_bucket_name = var.logs_bucket_name
  environment      = var.environment
}

module "guardduty" {
  source = "./modules/guardduty"
}

module "inspector" {
  source = "./modules/inspector"
}

module "waf" {
  source = "./modules/waf"
}

/* 
module "cloudtrail" {
  source = "./modules/cloudtrail"
  depends_on = [module.s3]
}
*/

module "lambda" {
  source           = "./modules/lambda"
  logs_bucket_name = module.s3.logs_bucket_name
  datadog_api_key  = var.datadog_api_key
  depends_on       = [module.s3, module.guardduty, module.inspector, module.waf]
}

module "datadog" {
  source          = "./modules/datadog"
  datadog_api_key = var.datadog_api_key
  datadog_app_key = var.datadog_app_key
  depends_on      = [module.guardduty, module.inspector, module.waf, module.lambda]
}

# Output the S3 bucket name
output "logs_bucket_name" {
  value = module.s3.logs_bucket_name
}
