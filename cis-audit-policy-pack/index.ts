/**
 * Scratch policy pack used to audit the neo-workshop-incident/dev stack
 * against the CIS AWS Foundations Benchmark. Advisory only (report, don't
 * block). Not intended to be merged - used for a one-off pulumi preview scan.
 */
import { PolicyPack } from "@pulumi/policy";
import { policyManager } from "@pulumi/compliance-policy-manager";

new PolicyPack("cis-aws-benchmark-audit", {
    policies: [
        // Policies explicitly tagged "cis" in this library (IAM password policy,
        // group-only policy attachment, S3 public read).
        ...policyManager.selectPolicies(
            {
                vendors: ["aws"],
                frameworks: ["cis"],
            },
            "advisory",
        ),
        // Additional CIS AWS Foundations Benchmark controls (storage/RDS
        // encryption at rest, RDS public access) that are relevant to this
        // stack's resource types but aren't tagged "cis" in this library
        // version.
        ...policyManager.selectPoliciesByName(
            [
                "aws-s3-bucket-enable-server-side-encryption",
                "aws-rds-instance-disallow-unencrypted-storage",
                "aws-rds-instance-disallow-public-access",
            ],
            "advisory",
        ),
    ],
});
