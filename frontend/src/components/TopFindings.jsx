import "./TopFindings.css";

function TopFindings({ findings = [] }) {

  const getColor = (severity) => {
    switch ((severity || "").toUpperCase()) {
      case "CRITICAL":
        return "#991b1b";
      case "HIGH":
        return "#dc2626";
      case "MEDIUM":
        return "#f59e0b";
      case "LOW":
        return "#16a34a";
      default:
        return "#94a3a0";
    }
  };

  const getService = (finding) => {
    if (finding.bucket) return "Amazon S3";
    if (finding.user) return "AWS IAM";
    if (finding.instance) return "Amazon EC2";
    if (finding.database) return "Amazon RDS";
    if (finding.function) return "AWS Lambda";

    return finding.service || "AWS";
  };

  const getResource = (finding) => {
    return (
      finding.bucket ||
      finding.user ||
      finding.instance ||
      finding.database ||
      finding.function ||
      finding.resource ||
      "-"
    );
  };

  return (
    <div className="topfindings-card">

      <div className="topfindings-header">
        <div>
          <h2>Top Security Findings</h2>

          <p>
            Highest priority findings from the latest AWS security scan.
          </p>
        </div>
      </div>

      {findings.length === 0 ? (

        <div className="empty-box">
          <h3>No findings available</h3>

          <p>
            Your latest scan did not return any security findings.
          </p>
        </div>

      ) : (

        findings.slice(0, 5).map((finding, index) => (

          <div
            key={finding.id || finding.finding_id || index}
            className="finding-card"
            style={{
              borderLeft: `6px solid ${getColor(
                finding.severity
              )}`,
            }}
          >

            <div className="finding-top">

              <h3>
                {finding.issue || "Security Finding"}
              </h3>

              <span
                className="severity-pill"
                style={{
                  background: getColor(
                    finding.severity
                  ),
                }}
              >
                {finding.severity || "UNKNOWN"}
              </span>

            </div>

            <p className="finding-desc">
              {finding.recommendation ||
                "Review this security finding and apply the recommended remediation."}
            </p>

            <div className="finding-meta">

              <div>
                <strong>Service</strong>
                <span>
                  {getService(finding)}
                </span>
              </div>

              <div>
                <strong>Resource</strong>
                <span>
                  {getResource(finding)}
                </span>
              </div>

              <div>
                <strong>Status</strong>
                <span>
                  {finding.status || "OPEN"}
                </span>
              </div>

            </div>

          </div>

        ))

      )}

    </div>
  );
}

export default TopFindings;