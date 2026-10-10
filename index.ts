/**
 * The payment pipeline for the Sep 8 workshop.
 *
 * Shape borrowed from Engin Diri's "Incident Response as Code" post and its
 * companion repos (dirien/pulumi-pagerduty-fargate-demo), narrowed to what a
 * live demo can carry: no Fargate worker, no container image, just the chain:
 *
 *   payment queue --(failed receives)--> DLQ --> CloudWatch alarm --> SNS --> PagerDuty
 */
import * as aws from "@pulumi/aws";
import * as pagerduty from "@pulumi/pagerduty";
import * as pulumi from "@pulumi/pulumi";

const cfg = new pulumi.Config();
const contactEmail = cfg.get("pagerdutyEmail") ?? "workshop@example.com";

// ---------------------------------------------------------------------------
// On-call: who gets woken up
// ---------------------------------------------------------------------------

const team = new pagerduty.Team("platform-team", {
    name: "Platform (Neo workshop)",
    description: "Owns the payment pipeline for the Sep 8 workshop demo.",
});

const onCall = new pagerduty.User("workshop-oncall", {
    name: "Workshop On-Call",
    email: contactEmail,
    role: "user",
});

new pagerduty.TeamMembership("oncall-platform", {
    userId: onCall.id,
    teamId: team.id,
    role: "manager",
});

// Schedule (v1), not Schedulev2: v2 models rotations as RRULEs, which is more
// machinery than a single always-on demo layer needs.
const schedule = new pagerduty.Schedule("primary", {
    name: "Platform primary",
    // PagerDuty only accepts its documented zone subset — America/Toronto isn't in it
    timeZone: "America/New_York",
    teams: [team.id],
    layers: [{
        name: "Always on",
        start: "2026-09-01T00:00:00-04:00",
        rotationVirtualStart: "2026-09-01T00:00:00-04:00",
        rotationTurnLengthSeconds: 60 * 60 * 24 * 7,
        users: [onCall.id],
    }],
});

const escalation = new pagerduty.EscalationPolicy("platform-escalation", {
    name: "Platform escalation",
    teams: team.id,
    numLoops: 1,
    rules: [{
        escalationDelayInMinutes: 10,
        targets: [{ type: "schedule_reference", id: schedule.id }],
    }],
});

const paymentService = new pagerduty.Service("payments", {
    name: "Payments",
    escalationPolicy: escalation.id,
    // Auto-resolve so a demo incident cleans itself up if the DLQ drains.
    autoResolveTimeout: "1800",
    acknowledgementTimeout: "600",
    alertCreation: "create_alerts_and_incidents",
});

const cloudwatchVendor = pagerduty.getVendorOutput({ name: "Amazon CloudWatch" });

const cloudwatchIntegration = new pagerduty.ServiceIntegration("payments-cloudwatch", {
    name: "Amazon CloudWatch",
    service: paymentService.id,
    vendor: cloudwatchVendor.id,
});

// ---------------------------------------------------------------------------
// The alerting path: alarm -> SNS -> PagerDuty
// ---------------------------------------------------------------------------

const callerIdentity = aws.getCallerIdentityOutput({});

// sns-kms-encryption-enabled: encrypt the topic with a customer-managed key.
// The AWS-managed alias/aws/sns key cannot be used here: its key policy cannot
// be edited to let CloudWatch Alarms publish, which would silently break paging.
const alarmTopicKey = new aws.kms.Key("payment-alarms-key", {
    description: "Encrypts the payment-alarms SNS topic",
    enableKeyRotation: true,
    policy: callerIdentity.accountId.apply(accountId => JSON.stringify({
        Version: "2012-10-17",
        Statement: [
            {
                // Keeps IAM policies in the account able to administer/use the key.
                Sid: "EnableAccountPermissions",
                Effect: "Allow",
                Principal: { AWS: `arn:aws:iam::${accountId}:root` },
                Action: "kms:*",
                Resource: "*",
            },
            {
                // CloudWatch Alarms publish to an encrypted topic via these actions.
                Sid: "AllowCloudWatchAlarms",
                Effect: "Allow",
                Principal: { Service: "cloudwatch.amazonaws.com" },
                Action: ["kms:Decrypt", "kms:GenerateDataKey*"],
                Resource: "*",
                Condition: { StringEquals: { "aws:SourceAccount": accountId } },
            },
        ],
    })),
});

const alarmTopic = new aws.sns.Topic("payment-alarms", {
    kmsMasterKeyId: alarmTopicKey.arn,
});

// The integration key is minted by PagerDuty and consumed here, so Pulumi will
// not create the subscription before the integration exists. No copy-paste step.
new aws.sns.TopicSubscription("payment-alarms-to-pagerduty", {
    topic: alarmTopic.arn,
    protocol: "https",
    endpoint: pulumi.interpolate`https://events.pagerduty.com/integration/${cloudwatchIntegration.integrationKey}/enqueue`,
    endpointAutoConfirms: true,
});

// ---------------------------------------------------------------------------
// The queues
// ---------------------------------------------------------------------------

const dlq = new aws.sqs.Queue("payment-dlq", {
    messageRetentionSeconds: 60 * 60 * 24,
});

const paymentQueue = new aws.sqs.Queue("payment-queue", {
    redrivePolicy: pulumi.jsonStringify({
        deadLetterTargetArn: dlq.arn,
        maxReceiveCount: 1,
    }),
    visibilityTimeoutSeconds: 5,
});

const dlqAlarm = new aws.cloudwatch.MetricAlarm("payment-dlq-alarm", {
    alarmDescription: "Messages are landing in the payment dead-letter queue",
    namespace: "AWS/SQS",
    metricName: "ApproximateNumberOfMessagesVisible",
    dimensions: { QueueName: dlq.name },
    statistic: "Maximum",
    period: 60,
    evaluationPeriods: 1,
    threshold: 1,
    comparisonOperator: "GreaterThanOrEqualToThreshold",
    treatMissingData: "notBreaching",
    alarmActions: [alarmTopic.arn],
    okActions: [alarmTopic.arn],
});

new aws.cloudwatch.MetricAlarm("payment-queue-age-alarm", {
    alarmDescription: "Oldest message in the payment queue is backing up",
    namespace: "AWS/SQS",
    metricName: "ApproximateAgeOfOldestMessage",
    dimensions: { QueueName: paymentQueue.name },
    statistic: "Maximum",
    period: 300,
    evaluationPeriods: 2,
    threshold: 900,
    comparisonOperator: "GreaterThanThreshold",
    treatMissingData: "notBreaching",
    // alarmActions intentionally omitted.
});

// ---------------------------------------------------------------------------
// Staging assets
// ---------------------------------------------------------------------------

// Where the payments team stages report exports before publishing.
const stagingBucket = new aws.s3.Bucket("payments-staging", {});

// CIS AWS hardening for the staging bucket.

// s3-bucket-versioning-enabled: an overwritten export is recoverable.
new aws.s3.BucketVersioningV2("payments-staging-versioning", {
    bucket: stagingBucket.id,
    versioningConfiguration: { status: "Enabled" },
});

// s3-bucket-encryption: SSE-S3 with bucket keys.
new aws.s3.BucketServerSideEncryptionConfigurationV2("payments-staging-sse", {
    bucket: stagingBucket.id,
    rules: [{
        applyServerSideEncryptionByDefault: { sseAlgorithm: "AES256" },
        bucketKeyEnabled: true,
    }],
});

// s3-bucket-level-public-access-prohibited: block all public access.
const stagingPublicAccessBlock = new aws.s3.BucketPublicAccessBlock("payments-staging-pab", {
    bucket: stagingBucket.id,
    blockPublicAcls: true,
    blockPublicPolicy: true,
    ignorePublicAcls: true,
    restrictPublicBuckets: true,
});

// s3-bucket-ssl-enforcement-required: deny any request not made over TLS.
// Depends on the public access block so the two don't race on the bucket.
new aws.s3.BucketPolicy("payments-staging-tls-only", {
    bucket: stagingBucket.id,
    policy: stagingBucket.arn.apply(arn => JSON.stringify({
        Version: "2012-10-17",
        Statement: [{
            Sid: "DenyInsecureTransport",
            Effect: "Deny",
            Principal: "*",
            Action: "s3:*",
            Resource: [arn, `${arn}/*`],
            Condition: { Bool: { "aws:SecureTransport": "false" } },
        }],
    })),
}, { dependsOn: [stagingPublicAccessBlock] });

// s3-bucket-logging-enabled: server access logs go to a dedicated log bucket.
// The log bucket is itself hardened, but is not self-logging (that would loop).
const accessLogsBucket = new aws.s3.Bucket("payments-staging-access-logs", {});

new aws.s3.BucketServerSideEncryptionConfigurationV2("payments-staging-access-logs-sse", {
    bucket: accessLogsBucket.id,
    rules: [{
        applyServerSideEncryptionByDefault: { sseAlgorithm: "AES256" },
        bucketKeyEnabled: true,
    }],
});

const accessLogsPublicAccessBlock = new aws.s3.BucketPublicAccessBlock("payments-staging-access-logs-pab", {
    bucket: accessLogsBucket.id,
    blockPublicAcls: true,
    blockPublicPolicy: true,
    ignorePublicAcls: true,
    restrictPublicBuckets: true,
});

new aws.s3.BucketVersioningV2("payments-staging-access-logs-versioning", {
    bucket: accessLogsBucket.id,
    versioningConfiguration: { status: "Enabled" },
});

// Allow the S3 logging service to write, scoped to this source bucket and
// account (confused-deputy guard), and require TLS.
const accessLogsPolicy = new aws.s3.BucketPolicy("payments-staging-access-logs-policy", {
    bucket: accessLogsBucket.id,
    policy: pulumi.all([accessLogsBucket.arn, stagingBucket.arn, callerIdentity.accountId]).apply(
        ([logsArn, sourceArn, accountId]) => JSON.stringify({
            Version: "2012-10-17",
            Statement: [
                {
                    Sid: "AllowS3ServerAccessLogs",
                    Effect: "Allow",
                    Principal: { Service: "logging.s3.amazonaws.com" },
                    Action: "s3:PutObject",
                    Resource: `${logsArn}/*`,
                    Condition: {
                        ArnLike: { "aws:SourceArn": sourceArn },
                        StringEquals: { "aws:SourceAccount": accountId },
                    },
                },
                {
                    Sid: "DenyInsecureTransport",
                    Effect: "Deny",
                    Principal: "*",
                    Action: "s3:*",
                    Resource: [logsArn, `${logsArn}/*`],
                    Condition: { Bool: { "aws:SecureTransport": "false" } },
                },
            ],
        })),
}, { dependsOn: [accessLogsPublicAccessBlock] });

new aws.s3.BucketLoggingV2("payments-staging-logging", {
    bucket: stagingBucket.id,
    targetBucket: accessLogsBucket.id,
    targetPrefix: "payments-staging/",
}, { dependsOn: [accessLogsPolicy] });

// ---------------------------------------------------------------------------
// The database behind the service
// ---------------------------------------------------------------------------

const db = new aws.rds.Instance("payments-db", {
    engine: "postgres",
    instanceClass: "db.t4g.micro",
    allocatedStorage: 20,
    maxAllocatedStorage: 20,
    dbName: "payments",
    username: "payments",
    manageMasterUserPassword: true,
    skipFinalSnapshot: true,
    applyImmediately: true,
    publiclyAccessible: false,
    // CIS AWS hardening.
    // rds-encryption-enabled: encrypt storage at rest. Changing this on an
    // existing instance forces replacement.
    storageEncrypted: true,
    // rds-db-instance-backup-enabled: automated backups, 7-day retention.
    backupRetentionPeriod: 7,
    // rds-instance-logging-enabled: ship engine logs to CloudWatch Logs.
    enabledCloudwatchLogsExports: ["postgresql", "upgrade"],
});

export const paymentQueueUrl = paymentQueue.url;
export const dlqUrl = dlq.url;
export const dlqArn = dlq.arn;
export const alarmName = dlqAlarm.name;
export const dbIdentifier = db.identifier;
export const pagerdutyServiceUrl = paymentService.htmlUrl;
export const stagingBucketName = stagingBucket.bucket;
