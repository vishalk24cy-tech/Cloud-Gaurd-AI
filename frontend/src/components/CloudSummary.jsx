import { useMemo } from "react";
import "./CloudSummary.css";

function CloudSummary({
  dashboard = {},
  accounts = null,
  history = [],
}) {
  const summary = useMemo(() => {
    const safeDashboard =
      dashboard && typeof dashboard === "object"
        ? dashboard
        : {};

    const safeHistory = Array.isArray(history)
      ? history
      : [];

    // =========================
    // ACCOUNTS
    // =========================

    const accountCount = Array.isArray(accounts)
      ? accounts.length
      : 0;

    // =========================
    // FINDINGS
    // =========================

    let findings = 0;

    safeHistory.forEach((scan) => {
      if (!scan || typeof scan !== "object") return;

      if (Array.isArray(scan.findings)) {
        findings += scan.findings.length;
      } else if (
        typeof scan.findings_count === "number"
      ) {
        findings += scan.findings_count;
      }
    });

    if (findings === 0) {
      findings =
        Number(
          safeDashboard.total_findings ??
            safeDashboard.findings ??
            safeDashboard.high_risk_findings ??
            0
        ) || 0;
    }

    // =========================
    // RESOURCES
    // =========================

    let ec2 = 0;
    let s3 = 0;
    let iam = 0;
    let lambda = 0;

    safeHistory.forEach((scan) => {
      if (!scan || typeof scan !== "object") return;

      const resources =
        scan.resources &&
        typeof scan.resources === "object"
          ? scan.resources
          : {};

      ec2 += Number(resources.ec2 ?? 0) || 0;
      s3 += Number(resources.s3 ?? 0) || 0;
      iam += Number(resources.iam ?? 0) || 0;
      lambda += Number(resources.lambda ?? 0) || 0;
    });

    if (
      ec2 === 0 &&
      s3 === 0 &&
      iam === 0 &&
      lambda === 0
    ) {
      const dashboardResources =
        safeDashboard.resources &&
        typeof safeDashboard.resources === "object"
          ? safeDashboard.resources
          : {};

      ec2 =
        Number(
          dashboardResources.ec2 ??
            safeDashboard.ec2 ??
            0
        ) || 0;

      s3 =
        Number(
          dashboardResources.s3 ??
            safeDashboard.s3 ??
            0
        ) || 0;

      iam =
        Number(
          dashboardResources.iam ??
            safeDashboard.iam ??
            0
        ) || 0;

      lambda =
        Number(
          dashboardResources.lambda ??
            safeDashboard.lambda ??
            0
        ) || 0;
    }

    // =========================
    // LAST SCAN
    // =========================

    let lastScan = "Never";
    let scanDate = null;

    if (safeHistory.length > 0) {
      const validDates = safeHistory
        .map((scan) => {
          if (!scan) return null;

          const value =
            scan.scan_time ??
            scan.created_at ??
            scan.timestamp;

          if (!value) return null;

          const date = new Date(value);

          return Number.isNaN(date.getTime())
            ? null
            : date;
        })
        .filter(Boolean);

      if (validDates.length > 0) {
        scanDate = new Date(
          Math.max(
            ...validDates.map((date) =>
              date.getTime()
            )
          )
        );
      }
    }

    if (!scanDate) {
      const dashboardScan =
        safeDashboard.last_scan ??
        safeDashboard.last_scan_at ??
        safeDashboard.scan_time;

      if (dashboardScan) {
        const date = new Date(dashboardScan);

        if (!Number.isNaN(date.getTime())) {
          scanDate = date;
        }
      }
    }

    if (scanDate) {
      lastScan = scanDate.toLocaleString();
    }

    // =========================
    // RISK
    // =========================

    let risk = "LOW";

    if (findings > 20) {
      risk = "CRITICAL";
    } else if (findings > 10) {
      risk = "HIGH";
    } else if (findings > 5) {
      risk = "MEDIUM";
    }

    if (safeDashboard.risk_level) {
      risk = String(
        safeDashboard.risk_level
      ).toUpperCase();
    } else if (safeDashboard.risk) {
      risk = String(
        safeDashboard.risk
      ).toUpperCase();
    }

    // =========================
    // COMPLIANCE
    // =========================

    let compliance =
      Number(
        safeDashboard.compliance ??
          safeDashboard.compliance_score ??
          0
      ) || 0;

    if (compliance <= 0) {
      compliance = 100 - findings * 2;
    }

    compliance = Math.max(
      0,
      Math.min(100, compliance)
    );

    return {
      accounts: accountCount,
      ec2,
      s3,
      iam,
      lambda,
      findings,
      compliance,
      risk,
      lastScan,
      hasScanData: safeHistory.length > 0,
    };
  }, [dashboard, accounts, history]);

  // =========================
  // CARDS
  // =========================

  const cards = useMemo(
    () => [
      {
        title: "AWS Accounts",
        value: summary.accounts,
        color: "emerald",
      },
      {
        title: "EC2 Instances",
        value: summary.ec2,
        color: "green",
      },
      {
        title: "S3 Buckets",
        value: summary.s3,
        color: "orange",
      },
      {
        title: "IAM Users",
        value: summary.iam,
        color: "purple",
      },
      {
        title: "Lambda Functions",
        value: summary.lambda,
        color: "red",
      },
      {
        title: "Security Findings",
        value: summary.findings,
        color: "yellow",
      },
      {
        title: "Compliance",
        value: `${summary.compliance}%`,
        color: "emerald",
      },
      {
        title: "Risk Level",
        value: summary.risk,
        color: "pink",
      },
    ],
    [summary]
  );

  // =========================
  // RENDER
  // =========================

  return (
    <div className="cloud-summary">

      {/* HEADER */}

      <div className="summary-header">
        <div>
          <h2>
            Enterprise Cloud Overview
          </h2>

          <p>
            Cloud infrastructure and security posture from your scan history
          </p>
        </div>

        <div className="scan-info">
          <span>Last Scan</span>

          <strong>
            {summary.lastScan}
          </strong>
        </div>
      </div>

      {/* SUMMARY CARDS */}

      <div className="summary-grid">
        {cards.map((card) => {
          const value = card.title === "AWS Accounts" || summary.hasScanData
            ? card.value
            : "—";
          const rawValue = String(
            value ?? ""
          );

          const numericValue = Number(
            rawValue.replace("%", "")
          );

          const progressWidth =
            Number.isFinite(numericValue)
              ? Math.max(
                  0,
                  Math.min(
                    numericValue,
                    100
                  )
                )
              : 0;

          return (
            <div
              className={`summary-card ${card.color}`}
              key={card.title}
            >
              <div className="card-top">
                <span className="card-title">
                  {card.title}
                </span>

                <span className="card-status">
                  {summary.lastScan === "Never" ? "NO DATA" : "LAST SCAN"}
                </span>
              </div>

              <div className="card-value">
                {value}
              </div>

              <div className="progress">
                <div
                  className="progress-fill"
                  style={{
                    width: `${progressWidth}%`,
                  }}
                />
              </div>
            </div>
          );
        })}
      </div>

      {/* ENTERPRISE PANEL */}

      <div className="enterprise-panel">

        {/* RISK */}

        <div className="risk-box">
          <h3>
            Overall Risk
          </h3>

          <div
            className={`risk-badge ${String(
              summary.risk
            ).toLowerCase()}`}
          >
            {summary.risk}
          </div>
        </div>

        {/* COMPLIANCE */}

        <div className="compliance-box">
          <h3>
            Compliance Score
          </h3>

          <div className="score">
            {summary.compliance}%
          </div>
        </div>

        {/* FINDINGS */}

        <div className="finding-box">
          <h3>
            Security Findings
          </h3>

          <div className="score">
            {summary.findings}
          </div>
        </div>

      </div>
    </div>
  );
}

export default CloudSummary;