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

// CIS: SNS topics must be encrypted with a customer managed KMS key (the
// AWS-managed alias/aws/sns key cannot be used with CloudWatch alarm actions).
// The key policy lets CloudWatch publish to the encrypted topic.
const alarmTopicKey = new aws.kms.Key("payment-alarms-key", {
    description: "Encrypts the payment alarm SNS topic",
    enableKeyRotation: true,
    policy: callerIdentity.accountId.apply(accountId => JSON.stringify({
        Version: "2012-10-17",
        Statement: [
            {
                Sid: "EnableAccountAdministration",
                Effect: "Allow",
                Principal: { AWS: `arn:aws:iam::${accountId}:root` },
                Action: "kms:*",
                Resource: "*",
            },
            {
                Sid: "AllowCloudWatchAlarmsToPublish",
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

// CIS: keep prior object versions so an overwritten export can be recovered.
new aws.s3.BucketVersioningV2("payments-staging-versioning", {
    bucket: stagingBucket.id,
    versioningConfiguration: { status: "Enabled" },
});

// CIS: server-side encryption at rest.
new aws.s3.BucketServerSideEncryptionConfigurationV2("payments-staging-sse", {
    bucket: stagingBucket.id,
    rules: [{
        applyServerSideEncryptionByDefault: { sseAlgorithm: "AES256" },
    }],
});

// CIS: block all public access.
const stagingPublicAccessBlock = new aws.s3.BucketPublicAccessBlock("payments-staging-public-access", {
    bucket: stagingBucket.id,
    blockPublicAcls: true,
    blockPublicPolicy: true,
    ignorePublicAcls: true,
    restrictPublicBuckets: true,
});

// CIS: require TLS for all requests.
new aws.s3.BucketPolicy("payments-staging-require-tls", {
    bucket: stagingBucket.id,
    policy: pulumi.jsonStringify({
        Version: "2012-10-17",
        Statement: [{
            Sid: "DenyInsecureTransport",
            Effect: "Deny",
            Principal: "*",
            Action: "s3:*",
            Resource: [stagingBucket.arn, pulumi.interpolate`${stagingBucket.arn}/*`],
            Condition: { Bool: { "aws:SecureTransport": "false" } },
        }],
    }),
}, { dependsOn: [stagingPublicAccessBlock] });

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
    // CIS: encrypt storage at rest, keep automated backups, export logs.
    storageEncrypted: true,
    backupRetentionPeriod: 7,
    enabledCloudwatchLogsExports: ["postgresql", "upgrade"],
});

export const paymentQueueUrl = paymentQueue.url;
export const dlqUrl = dlq.url;
export const dlqArn = dlq.arn;
export const alarmName = dlqAlarm.name;
export const dbIdentifier = db.identifier;
export const pagerdutyServiceUrl = paymentService.htmlUrl;
export const stagingBucketName = stagingBucket.bucket;
