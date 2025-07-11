import json
import boto3
import os
import time
import random
import logging
from datetime import datetime, timedelta
import requests
import numpy as np
from scipy import stats
import pandas as pd

# Configure logging
logger = logging.getLogger()
logger.setLevel(logging.INFO)

def lambda_handler(event, context):
    """
    Main Lambda function handler for anomaly detection
    Analyzes security data and sends anomalies to Datadog
    """
    try:
        # Initialize AWS clients
        s3_client = boto3.client('s3')
        
        # Get configuration from environment variables
        bucket_name = os.environ.get('LOGS_BUCKET_NAME', 'aws-security-monitoring-logs')
        datadog_api_key = os.environ.get('DATADOG_API_KEY')
        
        # Check if Datadog API key is configured
        if not datadog_api_key:
            logger.warning("Datadog API key not configured. No metrics will be sent to Datadog.")
        
        # Collect and process data
        data = collect_data(s3_client, bucket_name)
        
        if not data or data.empty:
            logger.info("No data found for analysis")
            return {
                'statusCode': 200,
                'body': json.dumps('No data found for analysis')
            }
        
        # Detect anomalies
        anomalies = detect_anomalies(data)
        
        # Send anomalies to Datadog if API key is available
        if datadog_api_key and anomalies:
            for anomaly in anomalies:
                send_to_datadog(anomaly, datadog_api_key)
        
        return {
            'statusCode': 200,
            'body': json.dumps(f'Anomaly detection completed. Found {len(anomalies)} anomalies.')
        }
        
    except Exception as e:
        logger.error(f"Error in anomaly detection: {str(e)}")
        return {
            'statusCode': 500,
            'body': json.dumps(f'Error in anomaly detection: {str(e)}')
        }

def collect_data(s3_client, bucket):
    """
    Collect and preprocess security data from S3 bucket
    """
    try:
        # Get list of objects in the bucket
        response = s3_client.list_objects_v2(Bucket=bucket)
        
        if 'Contents' not in response:
            logger.info(f"No contents found in bucket {bucket}")
            return pd.DataFrame()
        
        # Filter for objects modified in the last 24 hours
        now = datetime.now()
        yesterday = now - timedelta(days=1)
        
        recent_files = [
            obj['Key'] for obj in response['Contents']
            if obj['LastModified'].replace(tzinfo=None) > yesterday
        ]
        
        if not recent_files:
            logger.info("No recent files found for analysis")
            return pd.DataFrame()
        
        # Collect data from each file
        all_data = []
        for file_key in recent_files:
            try:
                # Skip if not a JSON file
                if not file_key.endswith('.json'):
                    continue
                    
                # Get the file content
                response = s3_client.get_object(Bucket=bucket, Key=file_key)
                file_content = response['Body'].read().decode('utf-8')
                data = json.loads(file_content)
                
                # Add source information and append to all_data
                if isinstance(data, list):
                    for item in data:
                        item['source'] = file_key.split('/')[0]  # guardduty, inspector, waf
                        all_data.append(item)
                else:
                    data['source'] = file_key.split('/')[0]
                    all_data.append(data)
                    
            except Exception as e:
                logger.warning(f"Error processing file {file_key}: {str(e)}")
                continue
        
        # Convert to DataFrame
        if all_data:
            df = pd.DataFrame(all_data)
            return df
        return pd.DataFrame()
        
    except Exception as e:
        logger.error(f"Error collecting data: {str(e)}")
        return pd.DataFrame()

def detect_anomalies(data):
    """
    Detect anomalies in security data using statistical methods
    """
    anomalies = []
    
    try:
        # Group data by source
        grouped = data.groupby('source')
        
        for source, group in grouped:
            # For GuardDuty
            if source == 'guardduty':
                # Look for high severity findings
                if 'severity' in group.columns:
                    high_severity = group[group['severity'] >= 7]
                    for _, finding in high_severity.iterrows():
                        anomalies.append({
                            'source': 'guardduty',
                            'type': 'high_severity',
                            'finding_id': finding.get('id', 'unknown'),
                            'severity': finding.get('severity', 0),
                            'description': finding.get('description', 'High severity GuardDuty finding'),
                            'timestamp': datetime.now().isoformat()
                        })
            
            # For Inspector
            elif source == 'inspector':
                # Look for critical findings
                if 'severity' in group.columns:
                    critical = group[group['severity'] == 'CRITICAL']
                    for _, finding in critical.iterrows():
                        anomalies.append({
                            'source': 'inspector',
                            'type': 'critical_finding',
                            'finding_id': finding.get('id', 'unknown'),
                            'severity': 'CRITICAL',
                            'description': finding.get('description', 'Critical Inspector finding'),
                            'timestamp': datetime.now().isoformat()
                        })
            
            # For WAF
            elif source == 'waf':
                # Look for blocked requests
                if 'action' in group.columns:
                    blocked = group[group['action'] == 'BLOCK']
                    if len(blocked) > 10:  # Threshold for anomaly
                        anomalies.append({
                            'source': 'waf',
                            'type': 'high_blocked_requests',
                            'count': len(blocked),
                            'description': f'Unusual number of blocked WAF requests: {len(blocked)}',
                            'timestamp': datetime.now().isoformat()
                        })
                        
        # Use statistical methods for general anomaly detection
        if 'timestamp' in data.columns and len(data) > 10:
            # Convert timestamp to datetime if it's not already
            if not pd.api.types.is_datetime64_any_dtype(data['timestamp']):
                data['timestamp'] = pd.to_datetime(data['timestamp'])
            
            # Group by hour and count events
            data['hour'] = data['timestamp'].dt.floor('H')
            hourly_counts = data.groupby(['source', 'hour']).size().reset_index(name='count')
            
            # Detect anomalies in counts
            for source, source_data in hourly_counts.groupby('source'):
                if len(source_data) > 5:  # Need enough data points
                    counts = source_data['count'].values
                    threshold = np.mean(counts) + 2 * np.std(counts)  # 2 sigma threshold
                    
                    for i, count in enumerate(counts):
                        if count > threshold:
                            anomalies.append({
                                'source': source,
                                'type': 'statistical_anomaly',
                                'count': count,
                                'threshold': threshold,
                                'hour': source_data.iloc[i]['hour'].isoformat(),
                                'description': f'Unusual activity detected in {source}',
                                'timestamp': datetime.now().isoformat()
                            })
                            
    except Exception as e:
        logger.error(f"Error in anomaly detection: {str(e)}")
        
    return anomalies

def send_to_datadog(anomaly, api_key):
    """
    Send detected anomalies to Datadog as metrics and events
    """
    # Datadog API endpoints
    metrics_url = "https://api.datadoghq.com/api/v1/series"
    events_url = "https://api.datadoghq.com/api/v1/events"
    
    # Current timestamp
    now = int(time.time())
    
    try:
        # Prepare headers
        headers = {
            "Content-Type": "application/json",
            "DD-API-KEY": api_key
        }
        
        # Send as metric
        source = anomaly.get('source', 'unknown')
        anomaly_type = anomaly.get('type', 'general')
        
        # Determine metric value
        if 'severity' in anomaly:
            # For findings with severity
            if isinstance(anomaly['severity'], str):
                # Map string severities to numbers
                severity_map = {
                    'LOW': 3,
                    'MEDIUM': 5,
                    'HIGH': 7,
                    'CRITICAL': 9
                }
                value = severity_map.get(anomaly['severity'].upper(), 5)
            else:
                value = float(anomaly['severity'])
        elif 'count' in anomaly:
            value = float(anomaly['count'])
        else:
            value = 1.0  # Default value
            
        # Create metrics payload
        metrics_payload = {
            "series": [
                {
                    "metric": f"aws.security.anomaly.{source}.{anomaly_type}",
                    "points": [[now, value]],
                    "type": "gauge",
                    "tags": [
                        f"source:{source}",
                        f"type:{anomaly_type}",
                        "monitor:anomaly_detection"
                    ]
                }
            ]
        }
        
        # Send metrics
        response = requests.post(metrics_url, headers=headers, json=metrics_payload)
        if response.status_code != 202:
            logger.warning(f"Failed to send metrics to Datadog: {response.text}")
        
        # Create event payload
        event_payload = {
            "title": f"Security Anomaly Detected: {source.upper()} - {anomaly_type}",
            "text": anomaly.get('description', 'Anomaly detected in AWS security monitoring'),
            "priority": "normal",
            "tags": [
                f"source:{source}",
                f"type:{anomaly_type}",
                "monitor:anomaly_detection"
            ],
            "alert_type": "warning"
        }
        
        # Send event
        response = requests.post(events_url, headers=headers, json=event_payload)
        if response.status_code != 202:
            logger.warning(f"Failed to send event to Datadog: {response.text}")
            
        logger.info(f"Successfully sent anomaly data to Datadog: {source} - {anomaly_type}")
        
    except Exception as e:
        logger.error(f"Error sending data to Datadog: {str(e)}")
