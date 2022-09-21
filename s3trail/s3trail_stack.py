from aws_cdk import (
    Duration,
    Stack,
    RemovalPolicy,
    aws_s3 as s3,
    aws_cloudtrail as cloudtrail,
    aws_iam as iam,
    aws_kms as kms,
    aws_logs as logs,
)
from constructs import Construct


class S3TrailStack(Stack):
    def __init__(self, scope: Construct, construct_id: str, **kwargs) -> None:
        super().__init__(scope, construct_id, **kwargs)

        permissions_boundary_policy_arn = self.node.try_get_context(
            "PermissionsBoundaryPolicyArn"
        )

        if not permissions_boundary_policy_arn:
            permissions_boundary_policy_name = self.node.try_get_context(
                "PermissionsBoundaryPolicyName"
            )
            if permissions_boundary_policy_name:
                permissions_boundary_policy_arn = self.format_arn(
                    service="iam",
                    region="",
                    account=self.account,
                    resource="policy",
                    resource_name=permissions_boundary_policy_name,
                )

        if permissions_boundary_policy_arn:
            policy = iam.ManagedPolicy.from_managed_policy_arn(
                self, "PermissionsBoundary", permissions_boundary_policy_arn
            )
            iam.PermissionsBoundary.of(self).apply(policy)

        # if a KMS key name is provided, enable bucket encryption
        s3kms_key_alias = self.node.try_get_context("S3KmsKeyAlias")
        if s3kms_key_alias:
            s3kms_key = kms.Key.from_lookup(
                self, "S3KmsKey", alias_name=s3kms_key_alias
            )
            s3kms_params = {
                "encryption": s3.BucketEncryption.KMS,
                "bucket_key_enabled": True,
                "encryption_key": s3kms_key,
            }
        else:
            s3kms_key = None
            s3kms_params = {}

        trail_key = kms.Key(
            self,
            "CloudtrailKey",
            alias=self.stack_name + "-trail-key",
            enable_key_rotation=True,
            pending_window=Duration.days(7),
            removal_policy=RemovalPolicy.DESTROY,
            # admins
            # description
            # enable_key_rotation
        )

        audited_bucket = s3.Bucket(
            self,
            "AuditedBucket",
            auto_delete_objects=True,
            removal_policy=RemovalPolicy.DESTROY,
            block_public_access=s3.BlockPublicAccess.BLOCK_ALL,
            event_bridge_enabled=True,
            **s3kms_params,
        )

        trail_key.grant_encrypt_decrypt(
            iam.ServicePrincipal(
                "cloudtrail.amazonaws.com",
                #  "TrailARN": "arn:aws:cloudtrail:us-east-1:286367598331:trail/S3TrailStack-s3trail67C4C9C6-lOf0wRPnOBrS",
                conditions={
                    "StringLike": {
                        "aws:SourceArn": self.format_arn(
                            service="cloudtrail",
                            region=self.region,
                            account=self.account,
                            resource="trail",
                            # use a wildcard so as to avoid a circular dependency
                            # between the trail and the key
                            resource_name=self.stack_name + "*",
                        )
                    }
                },
            )
        )

        s3trail = cloudtrail.Trail(
            self,
            "s3trail",
            # send_to_cloud_watch_logs=True,
            # cloud_watch_logs_retention=logs.RetentionDays.ONE_YEAR,
            include_global_service_events=False,
            is_multi_region_trail=False,
            encryption_key=trail_key,
            # management_events
            # s3_key_prefix
        )
        s3trail.apply_removal_policy(RemovalPolicy.DESTROY)

        # https://docs.aws.amazon.com/cdk/api/v2/python/aws_cdk.aws_cloudtrail/S3EventSelector.html#aws_cdk.aws_cloudtrail.S3EventSelector
        s3trail.add_s3_event_selector(
            [
                cloudtrail.S3EventSelector(
                    bucket=audited_bucket,
                    # object_prefix
                )
            ],
            # exclude_management_event_sources = [],
            include_management_events=False,
        )
