import aws_cdk as core
import aws_cdk.assertions as assertions

from s3trail.s3trail_stack import S3TrailStack

# example tests. To run these tests, uncomment this file along with the example
# resource in s3trail/s3trail_stack.py
def test_sqs_queue_created():
    app = core.App()
    stack = S3TrailStack(app, "s3trail")
    template = assertions.Template.from_stack(stack)


#     template.has_resource_properties("AWS::SQS::Queue", {
#         "VisibilityTimeout": 300
#     })
