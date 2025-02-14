import boto3
import argparse
import requests
import json
from typing import List, Dict
from datetime import datetime

def get_security_group_rules(ec2_client, group_ids: List[str]) -> List[Dict]:
    """Get inbound rules from security groups."""
    rules = []
    response = ec2_client.describe_security_groups(GroupIds=group_ids)
    
    for sg in response['SecurityGroups']:
        for rule in sg['IpPermissions']:
            port_info = {
                'FromPort': rule.get('FromPort', -1),
                'ToPort': rule.get('ToPort', -1),
                'Protocol': rule.get('IpProtocol', '-1'),
                'Source': [ip_range.get('CidrIp', '') for ip_range in rule.get('IpRanges', [])]
            }
            rules.append(port_info)
    
    return rules

def get_ztna_instances(regions: List[str], access_key: str = None, 
                      secret_key: str = None, session_token: str = None) -> List[Dict]:
    """Get EC2 instances with ztna_available=yes tag."""
    instances = []
    
    for region in regions:
        session = boto3.Session(
            aws_access_key_id=access_key,
            aws_secret_access_key=secret_key,
            aws_session_token=session_token,
            region_name=region
        )
        ec2 = session.client('ec2')
        
        response = ec2.describe_instances(
            Filters=[
                {
                    'Name': 'tag:ztna_available',
                    'Values': ['yes']
                }
            ]
        )
        
        for reservation in response['Reservations']:
            for instance in reservation['Instances']:
                security_group_ids = [sg['GroupId'] for sg in instance.get('SecurityGroups', [])]
                open_ports = get_security_group_rules(ec2, security_group_ids)
                
                instance_info = {
                    'InstanceId': instance['InstanceId'],
                    'InstanceType': instance['InstanceType'],
                    'LaunchTime': instance['LaunchTime'],
                    'Region': region,
                    'State': instance['State']['Name'],
                    'PublicIp': instance.get('PublicIpAddress', ''),
                    'PrivateIp': instance.get('PrivateIpAddress', ''),
                    'SecurityGroups': security_group_ids,
                    'OpenPorts': open_ports
                }
                
                if 'Tags' in instance:
                    instance_info['Tags'] = {
                        tag['Key']: tag['Value'] for tag in instance['Tags']
                    }
                
                instances.append(instance_info)
    
    return instances

def get_publishers_list(url: str, headers: Dict) -> List[Dict]:
    """Get list of Netskope publishers."""
    try:
        response = requests.get(
            f'{url}/api/v2/infrastructure/publishers?fields=publisher_id,publisher_name',
            headers=headers
        )
        response.raise_for_status()
        return response.json().get('data', {}).get('publishers', [])
    except requests.exceptions.RequestException as e:
        if args.debug:
            print(f"Failed to get publishers: {str(e)}")
            print("Response:", response.text)
        return []

def print_publishers(publishers: List[Dict]) -> None:
    """Print publishers list."""
    if not publishers:
        print("\nNo publishers found")
        return
    print("\nAvailable Publishers:")
    for pub in publishers:
        print(f"  - {pub.get('publisher_name', 'N/A')} (ID: {pub.get('publisher_id', 'N/A')})")

def create_netskope_payload(instance: Dict, publishers: List[Dict]) -> Dict:
    """Create the payload for Netskope API request."""
    protocols = []
    for rule in instance['OpenPorts']:
        if rule['Protocol'] in ['tcp', 'udp']:
            if rule['FromPort'] == rule['ToPort']:
                protocols.append({
                    'port': str(rule['FromPort']),
                    'type': rule['Protocol']
                })
            else:
                for port in range(rule['FromPort'], rule['ToPort'] + 1):
                    protocols.append({
                        'port': str(port),
                        'type': rule['Protocol']
                    })
    
    
    # Find matching publisher
    publisher_tag = instance.get('Tags', {}).get('publisher')
    publishers_list = []
    if publisher_tag:
        for pub in publishers:
            if pub['publisher_name'] == publisher_tag:
                publishers_list = [{
                    'publisher_id': str(pub['publisher_id']),
                    'publisher_name': pub['publisher_name']
                }]
                break
    
    return {
        'app_name': f"EC2-{instance['InstanceId']}",
        'host': instance['PrivateIp'],
        'real_host': instance['PrivateIp'],
        'protocols': protocols,
        'clientless_access': False,
        'trust_self_signed_certs': True,
        'use_publisher_dns': False,
        'is_user_portal_app': False,
        'publishers': publishers_list
    }

def add_to_netskope(url: str, headers: Dict, payload: Dict) -> tuple:
    """Make the API call to Netskope. Returns (success, status_code, response)"""
    try:
        response = requests.post(url, headers=headers, json=payload)
        response.raise_for_status()
        return True, response.status_code, response.json() if response.text else "No response body"
    except requests.exceptions.RequestException as e:
        error_response = None
        try:
            error_response = e.response.json() if e.response and e.response.text else str(e)
        except:
            error_response = str(e)
        return False, getattr(e.response, 'status_code', None), error_response

def print_instance_summary(instances: List[Dict], output_format: str = 'detailed') -> None:
    """Print instance information."""
    if not instances:
        print("No instances with ztna_available=yes tag found.")
        return
    
    print(f"\nFound {len(instances)} ZTNA-available instances:\n")
    for instance in instances:
        if output_format == 'simple':
            ports = []
            for rule in instance['OpenPorts']:
                if rule['FromPort'] == rule['ToPort']:
                    ports.append(f"{rule['Protocol']}:{rule['FromPort']}")
                else:
                    ports.append(f"{rule['Protocol']}:{rule['FromPort']}-{rule['ToPort']}")
            ports_str = ', '.join(ports)
            print(f"{instance['InstanceId']} - IP: {instance['PublicIp']} - Open: {ports_str}")
        else:
            print(f"Instance ID: {instance['InstanceId']}")
            print(f"Type: {instance['InstanceType']}")
            print(f"Region: {instance['Region']}")
            print(f"Public IP: {instance['PublicIp']}")
            print(f"Private IP: {instance['PrivateIp']}")
            print(f"State: {instance['State']}")
            print("Open Ports:")
            for rule in instance['OpenPorts']:
                sources = ', '.join(rule['Source']) if rule['Source'] else 'None'
                if rule['FromPort'] == rule['ToPort']:
                    print(f"  - {rule['Protocol']}:{rule['FromPort']} from {sources}")
                else:
                    print(f"  - {rule['Protocol']}:{rule['FromPort']}-{rule['ToPort']} from {sources}")
            if instance.get('Tags'):
                print("Tags:")
                for key, value in instance['Tags'].items():
                    print(f"  - {key}: {value}")
            print("-" * 50)

def main():
    parser = argparse.ArgumentParser(description='Manage ZTNA EC2 instances and Netskope integration')
    parser.add_argument('--regions', nargs='+', required=True,
                      help='AWS regions to check (e.g., us-east-1 us-west-2)')
    parser.add_argument('--access-key', required=True,
                      help='AWS access key ID')
    parser.add_argument('--secret-key', required=True,
                      help='AWS secret access key')
    parser.add_argument('--session-token',
                      help='AWS session token (optional)')
    parser.add_argument('--format', choices=['detailed', 'simple'],
                      default='detailed', help='Output format')
    parser.add_argument('--netskope-url',
                      help='Netskope API URL (e.g., https://tenant.goskope.com)')
    parser.add_argument('--netskope-token',
                      help='Netskope API token')
    parser.add_argument('--debug', action='store_true',
                      help='Show API request and response details')
    parser.add_argument('--add-to-netskope', action='store_true',
                      help='Add instances to Netskope as private apps')
    
    args = parser.parse_args()
    
    try:
        instances = get_ztna_instances(
            args.regions,
            args.access_key,
            args.secret_key,
            args.session_token
        )
        
        print_instance_summary(instances, args.format)
        
        if args.netskope_url and args.netskope_token:
            headers = {
                'accept': 'application/json',
                'Content-Type': 'application/json',
                'Authorization': f'Bearer {args.netskope_token}'
            }
            publishers = get_publishers_list(args.netskope_url, headers)
            print_publishers(publishers)
        
        if args.add_to_netskope:
            if not args.netskope_url or not args.netskope_token:
                print("Error: --netskope-url and --netskope-token required for adding to Netskope")
                return
            
            headers = {
                'accept': 'application/json',
                'Content-Type': 'application/json',
                'Authorization': f'Bearer {args.netskope_token}'
            }
            
            print("\nAdding instances to Netskope...")
            for instance in instances:
                netskope_url = f'{args.netskope_url}/api/v2/steering/apps/private'
                payload = create_netskope_payload(instance, publishers)
                
                if args.debug:
                    print(f"\nRequest for {instance['InstanceId']}:")
                    print("URL:", netskope_url)
                    print("Headers:", json.dumps({k:v for k,v in headers.items() if k != 'Authorization'}, indent=2))
                    print("Payload:", json.dumps(payload, indent=2))
                
                success, status_code, response = add_to_netskope(netskope_url, headers, payload)
                
                if success:
                    print(f"Added {instance['InstanceId']} - Status: {status_code}")
                    if args.debug:
                        print("Response:", json.dumps(response, indent=2))
                else:
                    print(f"Failed {instance['InstanceId']} - Status: {status_code}")
                    if args.debug:
                        print("Error:", json.dumps(response, indent=2) if isinstance(response, dict) else response)
                
    except Exception as e:
        print(f"Error: {str(e)}")

if __name__ == "__main__":
    main()
