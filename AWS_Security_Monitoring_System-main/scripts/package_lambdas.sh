#!/bin/bash

# Create the directory if it doesn't exist
mkdir -p scripts

# Exit on any error
set -e

# Script to package Lambda functions for deployment
echo "Packaging Lambda functions for deployment..."

# Function to create zip file for a Lambda function
package_lambda() {
    local dir_name=$1
    local file_name=$2
    local output_name=$3
    
    echo "Packaging $dir_name/$file_name -> $dir_name/$output_name"
    
    # Change to the directory
    cd "lambda/$dir_name"
    
    # Zip the Python file
    zip -r "$output_name" "$file_name"
    
    # Return to the original directory
    cd ../../
    
    echo "✅ Created $dir_name/$output_name"
}

# Package the Lambda layer with dependencies
package_layer() {
    echo "Creating Lambda layer with dependencies..."
    
    # Create temporary directory structure
    mkdir -p temp/python
    
    # Install dependencies to the temporary directory
    pip3 install -r lambda/layer/requirements.txt -t temp/python
    
    # Create zip file
    cd temp
    zip -r ../lambda/layer/dependencies.zip python
    cd ..
    
    # Clean up
    rm -rf temp
    
    echo "✅ Created Lambda layer: lambda/layer/dependencies.zip"
}

# Package anomaly detection Lambda
package_lambda "anomaly_detection" "anomaly_detection.py" "anomaly_detection.zip"

# Package collector Lambdas
mkdir -p lambda/collectors
for collector in "guardduty" "inspector" "waf"; do
    # Create placeholder collectors if they don't exist
    if [ ! -f "lambda/collectors/${collector}_collector.py" ]; then
        echo "Creating placeholder for ${collector}_collector.py"
        cat > "lambda/collectors/${collector}_collector.py" << EOF
import json
import boto3
import os
import datetime
import requests

def lambda_handler(event, context):
    """
    Lambda function to collect data from ${collector^} and send to Datadog
    """
    print(f"Collecting data from ${collector^}...")
    
    # Get environment variables
    bucket_name = os.environ.get('LOGS_BUCKET', 'aws-security-monitoring-logs')
    datadog_api_key = os.environ.get('DATADOG_API_KEY')
    
    # Initialize AWS clients
    s3_client = boto3.client('s3')
    ${collector}_client = boto3.client('${collector == "inspector" ? "inspector2" : collector}')
    
    try:
        # Collect findings from ${collector^}
        findings = collect_findings(${collector}_client)
        
        # Save findings to S3
        if findings:
            save_to_s3(s3_client, bucket_name, findings, '${collector}')
        
        # Send metrics to Datadog if API key is available
        if datadog_api_key and findings:
            send_to_datadog(findings, datadog_api_key)
        
        return {
            'statusCode': 200,
            'body': json.dumps(f'Successfully collected {len(findings)} findings from ${collector^}')
        }
    
    except Exception as e:
        print(f"Error collecting ${collector} data: {str(e)}")
        return {
            'statusCode': 500,
            'body': json.dumps(f'Error collecting data: {str(e)}')
        }

def collect_findings(client):
    """
    Collect findings from ${collector^}
    """
    findings = []
    
    if '${collector}' == 'guardduty':
        # List detectors
        detectors = client.list_detectors()
        
        # Get findings for each detector
        for detector_id in detectors.get('DetectorIds', []):
            response = client.list_findings(
                DetectorId=detector_id,
                FindingCriteria={
                    'Criterion': {
                        'severity': {
                            'Gte': 4.0  # Medium to critical findings
                        }
                    }
                },
                MaxResults=50
            )
            
            if 'FindingIds' in response and response['FindingIds']:
                findings_response = client.get_findings(
                    DetectorId=detector_id,
                    FindingIds=response['FindingIds']
                )
                findings.extend(findings_response.get('Findings', []))
    
    elif '${collector}' == 'inspector':
        # List findings with CRITICAL or HIGH severity
        response = client.list_findings(
            filterCriteria={
                'severity': [
                    {'comparison': 'EQUALS', 'value': 'CRITICAL'},
                    {'comparison': 'EQUALS', 'value': 'HIGH'}
                ]
            },
            maxResults=50
        )
        
        if 'findings' in response:
            findings = response['findings']
    
    elif '${collector}' == 'waf':
        # List WebACLs
        acls = client.list_web_acls(Scope='REGIONAL')
        
        # Get sample of blocked requests for each WebACL
        for acl in acls.get('WebACLs', []):
            acl_id = acl['ARN']
            
            # Get sampled requests
            try:
                sample = client.get_sampled_requests(
                    WebAclArn=acl_id,
                    RuleMetricName='ALL',
                    Scope='REGIONAL',
                    TimeWindow={
                        'StartTime': datetime.datetime.now() - datetime.timedelta(hours=1),
                        'EndTime': datetime.datetime.now()
                    },
                    MaxItems=100
                )
                
                if 'SampledRequests' in sample:
                    for request in sample['SampledRequests']:
                        if request.get('Action') == 'BLOCK':
                            findings.append({
                                'acl_id': acl_id,
                                'request': request,
                                'timestamp': datetime.datetime.now().isoformat(),
                                'action': 'BLOCK'
                            })
            except Exception as e:
                print(f"Error getting sampled requests for ACL {acl_id}: {str(e)}")
    
    return findings

def save_to_s3(s3_client, bucket, data, source):
    """
    Save data to S3 bucket
    """
    timestamp = datetime.datetime.now().strftime("%Y%m%d-%H%M%S")
    key = f"{source}/findings-{timestamp}.json"
    
    s3_client.put_object(
        Bucket=bucket,
        Key=key,
        Body=json.dumps(data, default=str),
        ContentType='application/json'
    )
    
    print(f"Saved {len(data)} {source} findings to s3://{bucket}/{key}")

def send_to_datadog(data, api_key):
    """
    Send metrics to Datadog
    """
    url = "https://api.datadoghq.com/api/v1/series"
    headers = {
        "Content-Type": "application/json",
        "DD-API-KEY": api_key
    }
    
    # Current timestamp
    now = int(datetime.datetime.now().timestamp())
    
    # Convert findings to metrics
    series = [
        {
            "metric": "aws.${collector}.findings",
            "points": [[now, len(data)]],
            "type": "gauge",
            "tags": ["source:${collector}"]
        }
    ]
    
    # For GuardDuty, add severity metrics
    if '${collector}' == 'guardduty':
        severity_counts = {
            "low": 0,
            "medium": 0,
            "high": 0
        }
        
        for finding in data:
            severity = finding.get('Severity', 0)
            if severity >= 7.0:
                severity_counts["high"] += 1
            elif severity >= 4.0:
                severity_counts["medium"] += 1
            else:
                severity_counts["low"] += 1
        
        for severity, count in severity_counts.items():
            series.append({
                "metric": f"aws.guardduty.findings.{severity}",
                "points": [[now, count]],
                "type": "gauge",
                "tags": ["source:guardduty", f"severity:{severity}"]
            })
    
    # For WAF, count blocked requests
    if '${collector}' == 'waf':
        series.append({
            "metric": "aws.waf.blocked_requests",
            "points": [[now, len(data)]],
            "type": "gauge",
            "tags": ["source:waf", "action:block"]
        })
    
    # Send metrics
    payload = {"series": series}
    
    try:
        response = requests.post(url, headers=headers, json=payload)
        if response.status_code == 202:
            print(f"Successfully sent metrics to Datadog for {len(data)} ${collector} findings")
        else:
            print(f"Failed to send metrics to Datadog: {response.status_code} - {response.text}")
    except Exception as e:
        print(f"Error sending metrics to Datadog: {str(e)}")
EOF
    fi
    
    # Package the collector
    package_lambda "collectors" "${collector}_collector.py" "${collector}_collector.zip"
done

# Skip the Lambda layer creation
# package_layer
echo "Skipping Lambda layer creation - you may need to create it manually by installing requirements"
echo "All Lambda functions packaged successfully!" 