import json
import boto3
import botocore.exceptions
import time
import random


def get_user_input():
    region_list = input("Enter the list of allowed regions (comma-separated, e.g., us-east-1,us-east-2): ").split(',')
    target_id = input("Enter the target ID (OU or Account ID): ").strip()
    target_type = input("Is this target an 'ou' or 'account'? ").strip().lower()
    return {"region_list": region_list, "target_id": target_id, "target_type": target_type}


def generate_scp(region_list):
    policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Sid": "GRREGIONDENY",
                "Effect": "Deny",
                "Condition": {
                    "StringNotEquals": {
                        "aws:RequestedRegion": region_list
                    },
                    "ArnNotLike": {
                        "aws:PrincipalARN": [
                            "arn:aws:iam::*:role/AWSControlTowerExecution",
                            "arn:aws:iam::*:role/stacksets-exec-*"
                        ]
                    }
                },
                "Resource": "*",
                "NotAction": [
                    "a4b:*",
                    "access-analyzer:*",
                    "account:*",
                    "acm:*",
                    "activate:*",
                    "artifact:*",
                    "aws-marketplace-management:*",
                    "aws-marketplace:*",
                    "aws-portal:*",
                    "billing:*",
                    "billingconductor:*",
                    "budgets:*",
                    "ce:*",
                    "chatbot:*",
                    "chime:*",
                    "cloudfront:*",
                    "cloudtrail:LookupEvents",
                    "compute-optimizer:*",
                    "config:*",
                    "consoleapp:*",
                    "consolidatedbilling:*",
                    "cur:*",
                    "datapipeline:GetAccountLimits",
                    "devicefarm:*",
                    "directconnect:*",
                    "ec2:DescribeRegions",
                    "ec2:DescribeTransitGateways",
                    "ec2:DescribeVpnGateways",
                    "ecr-public:*",
                    "fms:*",
                    "freetier:*",
                    "globalaccelerator:*",
                    "health:*",
                    "iam:*",
                    "importexport:*",
                    "invoicing:*",
                    "iq:*",
                    "kms:*",
                    "license-manager:ListReceivedLicenses",
                    "lightsail:Get*",
                    "mobileanalytics:*",
                    "networkmanager:*",
                    "notifications-contacts:*",
                    "notifications:*",
                    "organizations:*",
                    "payments:*",
                    "pricing:*",
                    "quicksight:DescribeAccountSubscription",
                    "resource-explorer-2:*",
                    "route53-recovery-cluster:*",
                    "route53-recovery-control-config:*",
                    "route53-recovery-readiness:*",
                    "route53:*",
                    "route53domains:*",
                    "s3:CreateMultiRegionAccessPoint",
                    "s3:DeleteMultiRegionAccessPoint",
                    "s3:DescribeMultiRegionAccessPointOperation",
                    "s3:GetAccountPublicAccessBlock",
                    "s3:GetBucketLocation",
                    "s3:GetBucketPolicyStatus",
                    "s3:GetBucketPublicAccessBlock",
                    "s3:GetMultiRegionAccessPoint",
                    "s3:GetMultiRegionAccessPointPolicy",
                    "s3:GetMultiRegionAccessPointPolicyStatus",
                    "s3:GetStorageLensConfiguration",
                    "s3:GetStorageLensDashboard",
                    "s3:ListAllMyBuckets",
                    "s3:ListMultiRegionAccessPoints",
                    "s3:ListStorageLensConfigurations",
                    "s3:PutAccountPublicAccessBlock",
                    "s3:PutMultiRegionAccessPointPolicy",
                    "savingsplans:*",
                    "shield:*",
                    "sso:*",
                    "sts:*",
                    "support:*",
                    "supportapp:*",
                    "supportplans:*",
                    "sustainability:*",
                    "tag:GetResources",
                    "tax:*",
                    "trustedadvisor:*",
                    "vendor-insights:ListEntitledSecurityProfiles",
                    "waf-regional:*",
                    "waf:*",
                    "wafv2:*"
                ]
            }
        ]
    }
    return policy


def generate_scp_name(target_id, suffix=''):
    timestamp = int(time.time())
    random_str = ''.join(random.choices('abcdefghijklmnopqrstuvwxyz0123456789', k=6))
    return f"RegionDeny-{target_id}-{timestamp}-{random_str}-{suffix}"


def detach_existing_scp(org_client, target_id):
    """
    Detaches any SCP with a name starting with `RegionDeny-<target ID>` or its ARN.

    Parameters:
        org_client (boto3.Client): Boto3 Organizations client.
        target_id (str): Target identifier (OU or account ID).
    """
    try:
        attached_policies = org_client.list_policies_for_target(TargetId=target_id, Filter="SERVICE_CONTROL_POLICY")
        for policy in attached_policies.get("Policies", []):
            policy_name = policy.get("Name")
            policy_id = policy.get("Id")
            if policy_name.startswith(f"RegionDeny-{target_id}"):
                org_client.detach_policy(PolicyId=policy_id, TargetId=target_id)
                print(f"Detached SCP {policy_name} (ID: {policy_id}) from {target_id}")
    except botocore.exceptions.ClientError as e:
        print(f"Error detaching existing SCPs from {target_id}: {e}")


def attach_scp(org_client, scp_policy, scp_name, target_id):
    """
    Creates and attaches an SCP to the specified target.

    Parameters:
        org_client (boto3.Client): Boto3 Organizations client.
        scp_policy (dict): SCP policy content.
        scp_name (str): Name for the SCP.
        target_id (str): Target identifier (OU or account ID).
    """
    try:
        response = org_client.create_policy(
            Content=json.dumps(scp_policy),
            Description=f"SCP to restrict regions for {target_id}",
            Name=scp_name,
            Type="SERVICE_CONTROL_POLICY"
        )
        scp_id = response["Policy"]["PolicySummary"]["Id"]
        print(f"SCP created with ID: {scp_id}")

        # Attach the SCP
        org_client.attach_policy(PolicyId=scp_id, TargetId=target_id)
        print(f"SCP {scp_name} attached to {target_id}")
    except botocore.exceptions.ClientError as e:
        print(f"Error creating or attaching SCP {scp_name} to {target_id}: {e}")


def main():
    user_input = get_user_input()
    region_list = user_input['region_list']
    target_id = user_input['target_id']

    scp_name = generate_scp_name(target_id)
    scp_policy = generate_scp(region_list)

    # Use the awsorganisation profile
    session = boto3.Session(profile_name="awsorganisation")
    org_client = session.client('organizations')

    # Detach any existing SCPs
    detach_existing_scp(org_client, target_id)

    # Create and attach the new SCP
    attach_scp(org_client, scp_policy, scp_name, target_id)


if __name__ == "__main__":
    main()
