import { PolicyPack } from "@pulumi/policy";
import { policyManager } from "@pulumi/compliance-policy-manager";

// Diagnostic-only pack: evaluates this stack's declared resources against
// Pulumi's CIS AWS compliance-ready policies, restricted to the services
// this program actually uses. Advisory mode so it never blocks a deploy.
new PolicyPack("cis-aws-benchmark", {
    policies: [
        ...policyManager.selectPolicies({
            vendors: ["aws"],
            frameworks: ["cis"],
            services: ["s3", "rds", "sqs", "sns", "cloudwatch", "ec2"],
        }, "advisory"),
    ],
});
