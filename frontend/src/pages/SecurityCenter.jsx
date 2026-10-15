import { useEffect, useState } from "react";
import { AlertTriangle, Copy, RefreshCw, ShieldCheck } from "lucide-react";
import api from "../services/api";
import "./SecurityCenter.css";

function SecurityCenter() {
  const [scan, setScan] = useState(null);
  const [findings, setFindings] = useState([]);
  const [loading, setLoading] = useState(true);
  const [expandedFinding, setExpandedFinding] = useState(null);

  useEffect(() => {
    loadSecurity();
  }, []);

  const loadSecurity = async () => {
    try {
      setLoading(true);

      const response = await api.get("/cloud/history");

      const scans = response.data || [];

      if (scans.length > 0) {
        let latestScan = scans[0];

        if ((!Array.isArray(latestScan.findings) || latestScan.findings.length === 0) && (latestScan._id || latestScan.id)) {
          try {
            const scanId = latestScan._id || latestScan.id;
            const detailRes = await api.get(`/cloud/history/${scanId}`);
            latestScan = detailRes.data?.scan || detailRes.data?.data || detailRes.data || latestScan;
          } catch (e) {
            console.warn("Could not fetch full scan details for SecurityCenter:", e);
          }
        }

        setScan(latestScan);
        setFindings(latestScan.findings || []);
      } else {
        setScan(null);
        setFindings([]);
      }
    } catch (error) {
      console.error("Security Center Error:", error);
    } finally {
      setLoading(false);
    }
  };

  const normalizeSeverity = (severity) => {
    return String(severity || "").toUpperCase();
  };

  const getSeverityColor = (severity) => {
    switch (normalizeSeverity(severity)) {
      case "CRITICAL":
        return "#ef4444";

      case "HIGH":
        return "#f97316";

      case "MEDIUM":
        return "#f59e0b";

      case "LOW":
        return "#10b981";

      default:
        return "#94a3a0";
    }
  };

  const getService = (item) => {
    if (item.bucket) return "Amazon S3";
    if (item.user) return "AWS IAM";
    if (item.instance) return "Amazon EC2";
    if (item.database) return "Amazon RDS";
    if (item.function) return "AWS Lambda";

    return item.service || "AWS";
  };

  const getResource = (item) => {
    return (
      item.bucket ||
      item.user ||
      item.instance ||
      item.database ||
      item.function ||
      item.resource ||
      "-"
    );
  };

  const getWhyItMatters = (item) => {
    const issue = String(item.issue || "").toLowerCase();

    if (issue.includes("mfa")) {
      return "Without Multi-Factor Authentication, compromised passwords can allow attackers to access AWS resources and perform unauthorized actions.";
    }

    if (
      issue.includes("ssh") ||
      issue.includes("port 22")
    ) {
      return "Public SSH access allows attackers on the internet to continuously attempt connections against your infrastructure.";
    }

    if (
      issue.includes("port 80") ||
      issue.includes("http")
    ) {
      return "Public HTTP access can expose web services directly to the internet and increase the attack surface.";
    }

    if (
      issue.includes("port 443") ||
      issue.includes("https")
    ) {
      return "Although HTTPS is normally required for public web applications, unrestricted access should be reviewed according to the application's security requirements.";
    }

    if (
      issue.includes("public") &&
      issue.includes("s3")
    ) {
      return "Public S3 access can expose sensitive files and data to unauthorized users.";
    }

    if (issue.includes("cloudtrail")) {
      return "Without CloudTrail logging, security events and administrative activity may be difficult to investigate.";
    }

    if (issue.includes("kms")) {
      return "Customer-managed encryption keys provide greater control over encryption and key management.";
    }

    return "This configuration may increase the security exposure of your AWS environment and should be reviewed.";
  };

  const getAwsCommand = (item) => {
    const issue = String(item.issue || "").toLowerCase();

    if (issue.includes("ssh") || issue.includes("port 22")) {
      const groupId =
        item.security_group_id ||
        item.group_id ||
        item.resource ||
        "<SECURITY_GROUP_ID>";

      return `aws ec2 revoke-security-group-ingress --group-id ${groupId} --protocol tcp --port 22 --cidr 0.0.0.0/0`;
    }

    if (issue.includes("port 80")) {
      const groupId =
        item.security_group_id ||
        item.group_id ||
        item.resource ||
        "<SECURITY_GROUP_ID>";

      return `aws ec2 revoke-security-group-ingress --group-id ${groupId} --protocol tcp --port 80 --cidr 0.0.0.0/0`;
    }

    if (issue.includes("port 443")) {
      const groupId =
        item.security_group_id ||
        item.group_id ||
        item.resource ||
        "<SECURITY_GROUP_ID>";

      return `aws ec2 revoke-security-group-ingress --group-id ${groupId} --protocol tcp --port 443 --cidr 0.0.0.0/0`;
    }

    if (
      issue.includes("mfa") &&
      item.user
    ) {
      return `aws iam list-mfa-devices --user-name ${item.user}`;
    }

    if (
      issue.includes("public") &&
      issue.includes("s3")
    ) {
      const bucket =
        item.bucket || "<BUCKET_NAME>";

      return `aws s3api put-public-access-block --bucket ${bucket} --public-access-block-configuration BlockPublicAcls=true,IgnorePublicAcls=true,BlockPublicPolicy=true,RestrictPublicBuckets=true`;
    }

    if (issue.includes("cloudtrail")) {
      return "aws cloudtrail describe-trails";
    }

    return "# Review the recommendation before applying a remediation command";
  };

  const getTerraform = (item) => {
    const issue = String(item.issue || "").toLowerCase();

    if (
      issue.includes("ssh") ||
      issue.includes("port 22")
    ) {
      return `resource "aws_security_group_rule" "restrict_ssh" {
  type              = "ingress"
  from_port         = 22
  to_port           = 22
  protocol          = "tcp"
  cidr_blocks       = ["YOUR_TRUSTED_IP/32"]
  security_group_id = "YOUR_SECURITY_GROUP_ID"
}`;
    }

    if (issue.includes("port 80")) {
      return `resource "aws_security_group_rule" "restrict_http" {
  type              = "ingress"
  from_port         = 80
  to_port           = 80
  protocol          = "tcp"
  cidr_blocks       = ["YOUR_TRUSTED_IP/32"]
  security_group_id = "YOUR_SECURITY_GROUP_ID"
}`;
    }

    if (issue.includes("port 443")) {
      return `resource "aws_security_group_rule" "https_access" {
  type              = "ingress"
  from_port         = 443
  to_port           = 443
  protocol          = "tcp"
  cidr_blocks       = ["0.0.0.0/0"]
  security_group_id = "YOUR_SECURITY_GROUP_ID"
}`;
    }

    if (
      issue.includes("public") &&
      issue.includes("s3")
    ) {
      return `resource "aws_s3_bucket_public_access_block" "secure_bucket" {
  bucket = "YOUR_BUCKET_NAME"

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}`;
    }

    return `# Terraform remediation
# Review the finding and apply the recommended security configuration.`;
  };

  const toggleFinding = (index) => {
    if (expandedFinding === index) {
      setExpandedFinding(null);
    } else {
      setExpandedFinding(index);
    }
  };

  const copyToClipboard = async (text) => {
    try {
      await navigator.clipboard.writeText(text);
    } catch (error) {
      console.error("Copy failed:", error);
    }
  };

  if (loading) {
    return (
      <div className="security-loading">
        <div className="loading-spinner"></div>

        <p>
          Analyzing AWS security posture...
        </p>
      </div>
    );
  }

  const riskScore = scan?.risk_score ?? "—";

  const securityLevel =
    scan?.security_level || "Unknown";

  const account =
    scan?.account ||
    scan?.account_id ||
    "Unknown";

  const scanTime = scan?.scan_time
    ? new Date(scan.scan_time).toLocaleString()
    : "Unknown";

  const highRisk = findings.filter((item) => {
    const severity = normalizeSeverity(
      item.severity
    );

    return (
      severity === "HIGH" ||
      severity === "CRITICAL"
    );
  }).length;

  const criticalFindings = findings.filter((item) => (
    normalizeSeverity(item.severity) === "CRITICAL"
  )).length;

  const protectedResources = scan?.protected_resources ?? "—";

  return (
    <div className="security-page">

      {/* HEADER */}

      <div className="security-header">

        <div>

          <div className="security-title-row">

            <span className="security-icon">
              <ShieldCheck size={22} />
            </span>

            <h1>
              CloudGuardAI Security Center
            </h1>

          </div>

          <p>
            AWS security posture management and
            vulnerability monitoring.
          </p>

        </div>

        <button
          className="refresh-button"
          onClick={loadSecurity}
        >
            <RefreshCw size={15} /> Refresh
        </button>

      </div>


      {/* SCAN SUMMARY */}

      {scan && (
        <div className="scan-summary">

          <div>
            <span>AWS ACCOUNT</span>
            <strong>{account}</strong>
          </div>

          <div>
            <span>SECURITY LEVEL</span>

            <strong
              className={`security-level ${securityLevel.toLowerCase()}`}
            >
              {securityLevel}
            </strong>
          </div>

          <div>
            <span>TOTAL FINDINGS</span>

            <strong>
              {findings.length}
            </strong>
          </div>

          <div>
            <span>LAST SCAN</span>

            <strong>
              {scanTime}
            </strong>
          </div>

        </div>
      )}


      {/* STATISTICS */}

      <div className="security-stats">

        <div className="security-stat blue">

          <div className="stat-header">

            <span>
              SECURITY SCORE
            </span>

            <span className="stat-icon">
              <ShieldCheck size={18} />
            </span>

          </div>

          <h1>
            {riskScore}
          </h1>

          <p>
            AI calculated security score
          </p>

        </div>


        <div className="security-stat red">

          <div className="stat-header">

            <span>
              HIGH RISK ISSUES
            </span>

            <span className="stat-icon">
              <AlertTriangle size={18} />
            </span>

          </div>

          <h1>
            {highRisk}
          </h1>

          <p>
            Require attention
          </p>

        </div>

        <div className="security-stat critical">
          <div className="stat-header">
            <span>CRITICAL FINDINGS</span>
            <span className="stat-icon"><AlertTriangle size={18} /></span>
          </div>
          <h1>{criticalFindings}</h1>
          <p>Highest priority exposure</p>
        </div>


        <div className="security-stat green">

          <div className="stat-header">

            <span>
              PROTECTED RESOURCES
            </span>

            <span className="stat-icon">
              <ShieldCheck size={18} />
            </span>

          </div>

          <h1>
            {protectedResources}
          </h1>

          <p>
            Security controls active
          </p>

        </div>

      </div>


      {/* FINDINGS */}

      <div className="findings-section">

        <div className="section-heading">

          <div>

            <h2>
              Active Security Findings
            </h2>

            <p>
              Click a finding to inspect the
              security issue and remediation.
            </p>

          </div>

          <span className="finding-count">
            {findings.length} Findings
          </span>

        </div>


        {findings.length === 0 ? (

          <div className="no-findings">

            <div>
              <ShieldCheck size={26} />
            </div>

            <h3>
              No Security Findings
            </h3>

            <p>
              CloudGuardAI did not detect any
              security issues.
            </p>

          </div>

        ) : (

          findings.map((item, index) => {

            const severity =
              normalizeSeverity(item.severity);

            const severityColor =
              getSeverityColor(severity);

            const isExpanded =
              expandedFinding === index;

            const awsCommand =
              getAwsCommand(item);

            const terraform =
              getTerraform(item);

            return (

              <div
                className={`security-finding ${
                  isExpanded
                    ? "finding-expanded"
                    : ""
                }`}
                key={index}
                style={{
                  "--finding-color":
                    severityColor
                }}
              >

                {/* CLICKABLE HEADER */}

                <div
                  className="finding-click-area"
                  onClick={() =>
                    toggleFinding(index)
                  }
                >

                  <div className="finding-title">

                    <div className="finding-name">

                      <span className="finding-number">
                        #{index + 1}
                      </span>

                      <div>

                        <h3>
                          {item.issue ||
                            "Security Issue"}
                        </h3>

                        <span className="finding-service">
                          {getService(item)}
                        </span>

                      </div>

                    </div>

                    <div className="finding-right">

                      <span
                        className="severity-badge"
                        style={{
                          background:
                            severityColor
                        }}
                      >
                        {severity || "UNKNOWN"}
                      </span>

                      <span className="expand-icon">
                        {isExpanded
                          ? "⌃"
                          : "⌄"}
                      </span>

                    </div>

                  </div>

                </div>


                {/* EXPANDED DETAILS */}

                {isExpanded && (

                  <div className="finding-details">

                    {/* OVERVIEW */}

                    <div className="detail-grid">

                      <div className="detail-box">

                        <small>
                          SERVICE
                        </small>

                        <strong>
                          {getService(item)}
                        </strong>

                      </div>


                      <div className="detail-box">

                        <small>
                          RESOURCE
                        </small>

                        <strong>
                          {getResource(item)}
                        </strong>

                      </div>


                      <div className="detail-box">

                        <small>
                          SEVERITY
                        </small>

                        <strong
                          style={{
                            color:
                              severityColor
                          }}
                        >
                          {severity}
                        </strong>

                      </div>


                      <div className="detail-box">

                        <small>
                          STATUS
                        </small>

                        <strong>
                          {item.status ||
                            "Open"}
                        </strong>

                      </div>

                    </div>


                    {/* WHY */}

                    <div className="detail-section">

                      <div className="detail-heading">
                        <span><AlertTriangle size={15} /></span>

                        <h4>
                          Why is this dangerous?
                        </h4>
                      </div>

                      <p>
                        {getWhyItMatters(item)}
                      </p>

                    </div>


                    {/* RECOMMENDATION */}

                    <div className="detail-section recommendation-box">

                      <div className="detail-heading">
                        <span><ShieldCheck size={15} /></span>

                        <h4>
                          Recommended Action
                        </h4>
                      </div>

                      <p>
                        {item.recommendation ||
                          "Review the affected AWS resource and apply the recommended security best practice."}
                      </p>

                    </div>


                    {/* AWS CLI */}

                    <div className="code-section">

                      <div className="code-header">

                        <div>
                          <span>›_</span>

                          <strong>
                            AWS CLI Remediation
                          </strong>
                        </div>

                        <button
                          onClick={(event) => {
                            event.stopPropagation();

                            copyToClipboard(
                              awsCommand
                            );
                          }}
                        >
                          <Copy size={13} /> Copy
                        </button>

                      </div>

                      <pre>
                        {awsCommand}
                      </pre>

                    </div>


                    {/* TERRAFORM */}

                    <div className="code-section">

                      <div className="code-header">

                        <div>
                          <span>&lt;/&gt;</span>

                          <strong>
                            Terraform Remediation
                          </strong>
                        </div>

                        <button
                          onClick={(event) => {
                            event.stopPropagation();

                            copyToClipboard(
                              terraform
                            );
                          }}
                        >
                          <Copy size={13} /> Copy
                        </button>

                      </div>

                      <pre>
                        {terraform}
                      </pre>

                    </div>


                    {/* STATUS */}

                    <div className="remediation-footer">

                      <div>

                        <span className="status-dot"></span>

                        <strong>
                          Remediation Available
                        </strong>

                      </div>

                      <span>
                        Review before applying
                      </span>

                    </div>

                  </div>

                )}

              </div>
            );
          })

        )}

      </div>

    </div>
  );
}

export default SecurityCenter;