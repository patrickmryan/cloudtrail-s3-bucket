from aws_cdk import (
    # Duration,
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
                print(permissions_boundary_policy_arn)

        if permissions_boundary_policy_arn:
            policy = iam.ManagedPolicy.from_managed_policy_arn(
                self, "PermissionsBoundary", permissions_boundary_policy_arn
            )
            iam.PermissionsBoundary.of(self).apply(policy)

        # if a KMS key name is provided, enable bucket encryption
        kms_key_alias = self.node.try_get_context("KmsKeyAlias")
        if kms_key_alias:
            kms_key = kms.Key.from_lookup(self, "KmsS3Key", alias_name=kms_key_alias)
            kms_params = {
                "encryption": s3.BucketEncryption.KMS,
                "bucket_key_enabled": True,
                "encryption_key": kms_key,
            }
        else:
            kms_key = None
            kms_params = {}

        logs_bucket = s3.Bucket(self, "LogsBucket", **kms_params)

        audited_bucket = s3.Bucket(
            self,
            "AuditedBucket",
            auto_delete_objects=True,
            removal_policy=RemovalPolicy.DESTROY,
            event_bridge_enabled=True,
            **kms_params,
            # server_access_logs_bucket=logs_bucket,
            # server_access_logs_prefix="AuditedBucket",
        )

        # logs_bucket.add_to_resource_policy(
        #     iam.PolicyStatement(
        #         principals=[iam.ServicePrincipal("logging.s3.amazonaws.com")],
        #         actions=["s3:PutObject"],
        #         resources=[logs_bucket.arn_for_objects('*')]
        #     )
        # )
        # logs_bucket.grant_put(iam.ServicePrincipal("logging.s3.amazonaws.com"))

        trail = self.trail_for_bucket(bucket=audited_bucket, key=kms_key)

        # audited_bucket.grant_put(iam.ServicePrincipal("cloudtrail.amazonaws.com"))

    def trail_for_bucket(self, bucket, key):

        # https://docs.aws.amazon.com/cdk/api/v2/python/aws_cdk.aws_cloudtrail/Trail.html
        s3trail = cloudtrail.Trail(
            self,
            "s3trail",
            # send_to_cloud_watch_logs=True,
            # cloud_watch_logs_retention=logs.RetentionDays.ONE_YEAR,
            #   have to grant kms access to a principal
            encryption_key=key,
        )

        if key:
            key.grant_encrypt_decrypt(
                iam.ServicePrincipal(
                    "cloudtrail.amazonaws.com",
                    conditions={"StringEquals": {"aws:SourceArn": s3trail.trail_arn}},
                )
            )

        # s3trail.log_all_s3_data_events

        # https://docs.aws.amazon.com/cdk/api/v2/python/aws_cdk.aws_cloudtrail/S3EventSelector.html#aws_cdk.aws_cloudtrail.S3EventSelector
        s3trail.add_s3_event_selector(
            [
                cloudtrail.S3EventSelector(
                    bucket=bucket,
                    # object_prefix
                )
            ],
            # exclude_management_event_sources = [],
            include_management_events=False,
        )

        return s3trail
