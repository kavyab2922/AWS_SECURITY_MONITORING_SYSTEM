import json
import boto3
import os
from datetime import datetime, timedelta
import requests
from botocore.exceptions import ClientError

def lambda_handler(event, context):
    # Initialize AWS clients
    cloudtrail = boto3.client('cloudtrail')
    s3 = boto3.client('s3')
    
    # Get environment variables
    datadog_api_key = os.environ['DATADOG_API_KEY']
    logs_bucket = os.environ['LOGS_BUCKET']
    
    try:
        # Get CloudTrail events from the last 15 minutes
        end_time = datetime.now()
        start_time = end_time - timedelta(minutes=15)
        
        events = cloudtrail.lookup_events(
            StartTime=start_time,
            EndTime=end_time,
            LookupAttributes=[
                {
                    'AttributeKey': 'EventName',
                    'AttributeValue': 'ConsoleLogin'
                },
                {
                    'AttributeKey': 'EventName',
                    'AttributeValue': 'CreateUser'
                },
                {
                    'AttributeKey': 'EventName',
                    'AttributeValue': 'DeleteUser'
                },
                {
                    'AttributeKey': 'EventName',
                    'AttributeValue': 'AttachUserPolicy'
                },
                {
                    'AttributeKey': 'EventName',
                    'AttributeValue': 'DetachUserPolicy'
                },
                {
                    'AttributeKey': 'EventName',
                    'AttributeValue': 'CreateAccessKey'
                },
                {
                    'AttributeKey': 'EventName',
                    'AttributeValue': 'DeleteAccessKey'
                },
                {
                    'AttributeKey': 'EventName',
                    'AttributeValue': 'CreateRole'
                },
                {
                    'AttributeKey': 'EventName',
                    'AttributeValue': 'DeleteRole'
                },
                {
                    'AttributeKey': 'EventName',
                    'AttributeValue': 'AssumeRole'
                }
            ]
        )
        
        if not events['Events']:
            return {
                'statusCode': 200,
                'body': json.dumps('No relevant CloudTrail events found')
            }
        
        # Process events
        processed_events = []
        for event in events['Events']:
            # Parse CloudTrail event
            cloudtrail_event = json.loads(event['CloudTrailEvent'])
            
            processed_event = {
                'event_id': event['EventId'],
                'event_name': event['EventName'],
                'event_time': event['EventTime'].isoformat(),
                'username': event['Username'],
                'resource_name': event.get('ResourceName', 'N/A'),
                'event_source': event['EventSource'],
                'aws_region': event['AwsRegion'],
                'source_ip': event.get('SourceIPAddress', 'N/A'),
                'user_agent': event.get('UserAgent', 'N/A'),
                'request_parameters': cloudtrail_event.get('requestParameters', {}),
                'response_elements': cloudtrail_event.get('responseElements', {}),
                'error_code': cloudtrail_event.get('errorCode', 'N/A'),
                'error_message': cloudtrail_event.get('errorMessage', 'N/A')
            }
            processed_events.append(processed_event)
            
            # Send to Datadog
            send_to_datadog(processed_event, datadog_api_key)
        
        # Store events in S3
        timestamp = datetime.now().strftime('%Y-%m-%d-%H-%M-%S')
        s3_key = f'cloudtrail/events-{timestamp}.json'
        
        s3.put_object(
            Bucket=logs_bucket,
            Key=s3_key,
            Body=json.dumps(processed_events)
        )
        
        return {
            'statusCode': 200,
            'body': json.dumps({
                'message': f'Processed {len(processed_events)} CloudTrail events',
                'events': processed_events
            })
        }
        
    except Exception as e:
        print(f"Error: {str(e)}")
        return {
            'statusCode': 500,
            'body': json.dumps({
                'error': str(e)
            })
        }

def send_to_datadog(event, api_key):
    """Send CloudTrail event to Datadog as a metric and event"""
    headers = {
        'Content-Type': 'application/json',
        'DD-API-KEY': api_key
    }
    
    # Determine event severity
    severity = 'info'
    if event['event_name'] in ['ConsoleLogin', 'AssumeRole']:
        severity = 'warning'
    elif event['event_name'] in ['CreateUser', 'DeleteUser', 'AttachUserPolicy', 'DetachUserPolicy']:
        severity = 'error'
    
    # Send as metric
    metric_data = {
        'series': [{
            'metric': 'aws.cloudtrail.events',
            'points': [[event['event_time'], 1]],
            'tags': [
                f'event_name:{event["event_name"]}',
                f'event_source:{event["event_source"]}',
                f'aws_region:{event["aws_region"]}',
                f'severity:{severity}'
            ]
        }]
    }
    
    requests.post(
        'https://api.datadoghq.com/api/v1/series',
        headers=headers,
        json=metric_data
    )
    
    # Send as event
    event_data = {
        'title': f'CloudTrail Event: {event["event_name"]}',
        'text': f'Event performed by {event["username"]} from {event["source_ip"]}',
        'tags': [
            f'event_name:{event["event_name"]}',
            f'event_source:{event["event_source"]}',
            f'aws_region:{event["aws_region"]}',
            f'username:{event["username"]}',
            f'source_ip:{event["source_ip"]}',
            f'resource_name:{event["resource_name"]}',
            f'severity:{severity}'
        ],
        'alert_type': severity,
        'source_type_name': 'cloudtrail'
    }
    
    requests.post(
        'https://api.datadoghq.com/api/v1/events',
        headers=headers,
        json=event_data
    ) 