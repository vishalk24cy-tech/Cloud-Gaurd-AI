import React, { useEffect, useMemo, useState } from "react";
import api from "../services/api";
import "./Compliance.css";

const FRAMEWORKS = {
  ALL: "ALL",
  CIS_AWS_Benchmark: "CIS_AWS_Benchmark",
  NIST_CSF: "NIST_CSF",
  PCI_DSS: "PCI_DSS",
};

const FRAMEWORK_LABELS = {
  ALL: "All Frameworks",
  CIS_AWS_Benchmark: "CIS AWS Benchmark",
  NIST_CSF: "NIST CSF",
  PCI_DSS: "PCI DSS",
};

const STATUS_CONFIG = {
  PASSED: {
    label: "Passed",
    className: "passed",
  },
  FAILED: {
    label: "Failed",
    className: "failed",
  },
  REVIEW: {
    label: "Review",
    className: "review",
  },
};

function normalizeStatus(value) {
  const status = String(value || "").toUpperCase();

  if (
    status === "PASS" ||
    status === "PASSED" ||
    status === "COMPLIANT"
  ) {
    return "PASSED";
  }

  if (
    status === "FAIL" ||
    status === "FAILED" ||
    status === "NON_COMPLIANT"
  ) {
    return "FAILED";
  }

  return "REVIEW";
}

function getScoreClass(score) {
  const value = Number(score || 0);

  if (value >= 90) return "excellent";
  if (value >= 75) return "good";
  if (value >= 50) return "warning";
  return "critical";
}

function getStatusClass(status) {
  const normalized = String(status || "").toUpperCase();

  if (
    normalized === "COMPLIANT" ||
    normalized === "PASSED"
  ) {
    return "compliant";
  }

  if (
    normalized === "AT_RISK" ||
    normalized === "REVIEW_REQUIRED"
  ) {
    return "at-risk";
  }

  if (normalized === "NON_COMPLIANT") {
    return "non-compliant";
  }

  return "not-assessed";
}

function formatDate(value) {
  if (!value) return "—";

  const date = new Date(value);

  if (Number.isNaN(date.getTime())) {
    return "—";
  }

  return date.toLocaleString(undefined, {
    year: "numeric",
    month: "short",
    day: "numeric",
    hour: "2-digit",
    minute: "2-digit",
  });
}

function formatFramework(framework) {
  return (
    FRAMEWORK_LABELS[framework] ||
    String(framework || "Unknown Framework")
      .replaceAll("_", " ")
      .replace(/\b\w/g, (letter) => letter.toUpperCase())
  );
}

function normalizeControls(result) {
  if (!result) return [];

  const controls =
    result.control_results ||
    result.controls_results ||
    result.controls?.results ||
    [];

  if (Array.isArray(controls)) {
    return controls.map((control, index) => ({
      id:
        control.control_id ||
        control.id ||
        `CONTROL-${index + 1}`,
      name:
        control.control_name ||
        control.name ||
        control.title ||
        control.issue ||
        "Security Control",
      status: normalizeStatus(
        control.status ||
          control.result ||
          control.control_status
      ),
      description:
        control.description ||
        control.issue ||
        control.title ||
        "No control description available.",
      evidence:
        control.evidence ||
        control.details ||
        control.observation ||
        {},
      findingId:
        control.finding_id ||
        control.findingId ||
        null,
      service:
        control.service ||
        control.resource_service ||
        null,
      resource:
        control.resource ||
        control.resource_arn ||
        null,
    }));
  }

  if (
    controls &&
    typeof controls === "object" &&
    !Array.isArray(controls)
  ) {
    return Object.entries(controls).map(
      ([key, value], index) => ({
        id: value?.control_id || key || `CONTROL-${index + 1}`,
        name:
          value?.control_name ||
          value?.name ||
          key,
        status: normalizeStatus(
          value?.status ||
            value?.result
        ),
        description:
          value?.description ||
          value?.issue ||
          "No control description available.",
        evidence:
          value?.evidence ||
          value?.details ||
          {},
        findingId:
          value?.finding_id ||
          null,
        service:
          value?.service ||
          null,
        resource:
          value?.resource ||
          null,
      })
    );
  }

  return [];
}

function extractFrameworkResult(compliance, framework) {
  if (!compliance) return null;

  const source =
    compliance.frameworks ||
    compliance.results ||
    {};

  return (
    source[framework] ||
    source[framework?.toUpperCase?.()] ||
    null
  );
}

function normalizeFrameworkCard(compliance, framework) {
  const result = extractFrameworkResult(
    compliance,
    framework
  );

  if (!result) {
    return {
      framework,
      score: 0,
      status: "NOT_ASSESSED",
      total: 0,
      passed: 0,
      failed: 0,
      review: 0,
      controls: [],
    };
  }

  const controls = normalizeControls(result);

  const total =
    Number(
      result.controls?.total ??
        result.total_controls ??
        result.total ??
        controls.length
    ) || 0;

  const passed =
    Number(
      result.controls?.passed ??
        result.passed_controls ??
        controls.filter(
          (item) => item.status === "PASSED"
        ).length
    ) || 0;

  const failed =
    Number(
      result.controls?.failed ??
        result.failed_controls ??
        controls.filter(
          (item) => item.status === "FAILED"
        ).length
    ) || 0;

  const review =
    Number(
      result.controls?.review ??
        result.review_controls ??
        controls.filter(
          (item) => item.status === "REVIEW"
        ).length
    ) || 0;

  return {
    framework,
    score: Number(result.score ?? 0),
    status:
      result.status ||
      (result.score >= 80
        ? "COMPLIANT"
        : "NON_COMPLIANT"),
    total,
    passed,
    failed,
    review,
    controls,
  };
}

function ScoreRing({ score, size = "large" }) {
  const normalized = Math.max(
    0,
    Math.min(100, Number(score || 0))
  );

  return (
    <div
      className={`compliance-score-ring ${size} ${getScoreClass(
        normalized
      )}`}
      style={{
        "--score": `${normalized * 3.6}deg`,
      }}
      aria-label={`Compliance score ${normalized} percent`}
    >
      <div className="compliance-score-ring-inner">
        <strong>{normalized}</strong>
        <span>/ 100</span>
      </div>
    </div>
  );
}

function FrameworkCard({
  framework,
  score,
  status,
  total,
  passed,
  failed,
  review,
  selected,
  onClick,
}) {
  return (
    <button
      type="button"
      className={`framework-card ${
        selected ? "selected" : ""
      }`}
      onClick={onClick}
      aria-pressed={selected}
    >
      <div className="framework-card-top">
        <div>
          <span className="framework-card-label">
            Framework
          </span>
          <h3>{formatFramework(framework)}</h3>
        </div>

        <span
          className={`framework-status ${getStatusClass(
            status
          )}`}
        >
          {String(status || "NOT_ASSESSED")
            .replaceAll("_", " ")}
        </span>
      </div>

      <div className="framework-score-row">
        <ScoreRing score={score} size="small" />

        <div className="framework-control-summary">
          <div>
            <span>Controls</span>
            <strong>{total}</strong>
          </div>

          <div>
            <span>Passed</span>
            <strong className="text-passed">
              {passed}
            </strong>
          </div>

          <div>
            <span>Failed</span>
            <strong className="text-failed">
              {failed}
            </strong>
          </div>

          <div>
            <span>Review</span>
            <strong className="text-review">
              {review}
            </strong>
          </div>
        </div>
      </div>
    </button>
  );
}

function Compliance() {
  const [dashboard, setDashboard] = useState(null);
  const [latest, setLatest] = useState(null);
  const [history, setHistory] = useState([]);
  const [trend, setTrend] = useState([]);
  const [statistics, setStatistics] = useState(null);

  const [selectedFramework, setSelectedFramework] =
    useState(FRAMEWORKS.ALL);

  const [selectedControl, setSelectedControl] =
    useState(null);

  const [loading, setLoading] = useState(true);
  const [refreshing, setRefreshing] = useState(false);
  const [error, setError] = useState("");

  const fetchComplianceData = async (
    showRefreshing = false
  ) => {
    try {
      if (showRefreshing) {
        setRefreshing(true);
      } else {
        setLoading(true);
      }

      setError("");

      const [
        dashboardResponse,
        latestResponse,
        historyResponse,
        trendResponse,
        statisticsResponse,
      ] = await Promise.allSettled([
        api.get("/compliance/"),
        api.get("/compliance/latest"),
        api.get("/compliance/history"),
        api.get("/compliance/trend"),
        api.get("/compliance/statistics"),
      ]);

      if (
        dashboardResponse.status === "fulfilled"
      ) {
        setDashboard(
          dashboardResponse.value?.data || null
        );
      }

      if (latestResponse.status === "fulfilled") {
        setLatest(
          latestResponse.value?.data || null
        );
      }

      if (historyResponse.status === "fulfilled") {
        const data =
          historyResponse.value?.data || {};

        setHistory(
          Array.isArray(data)
            ? data
            : data.history ||
                data.items ||
                data.snapshots ||
                []
        );
      }

      if (trendResponse.status === "fulfilled") {
        const data =
          trendResponse.value?.data || {};

        setTrend(
          Array.isArray(data)
            ? data
            : data.trend ||
                data.history ||
                data.items ||
                []
        );
      }

      if (
        statisticsResponse.status ===
        "fulfilled"
      ) {
        setStatistics(
          statisticsResponse.value?.data ||
            null
        );
      }

      const allFailed =
        dashboardResponse.status === "rejected" &&
        latestResponse.status === "rejected" &&
        historyResponse.status === "rejected" &&
        trendResponse.status === "rejected" &&
        statisticsResponse.status === "rejected";

      if (allFailed) {
        throw new Error(
          "Unable to load compliance data."
        );
      }
    } catch (err) {
      console.error(
        "Compliance data loading error:",
        err
      );

      setError(
        err?.response?.data?.detail ||
          err?.message ||
          "Unable to load compliance data."
      );
    } finally {
      setLoading(false);
      setRefreshing(false);
    }
  };

  useEffect(() => {
    fetchComplianceData();
  }, []);

  const compliance = dashboard?.compliance || dashboard;

  const frameworkCards = useMemo(() => {
    return [
      normalizeFrameworkCard(
        compliance,
        FRAMEWORKS.CIS_AWS_Benchmark
      ),
      normalizeFrameworkCard(
        compliance,
        FRAMEWORKS.NIST_CSF
      ),
      normalizeFrameworkCard(
        compliance,
        FRAMEWORKS.PCI_DSS
      ),
    ];
  }, [compliance]);

  const overallScore = useMemo(() => {
    if (!compliance) return 0;

    if (
      compliance.compliance_score !== undefined
    ) {
      return Number(
        compliance.compliance_score || 0
      );
    }

    const scores = frameworkCards
      .map((item) => item.score)
      .filter((score) => Number.isFinite(score));

    if (!scores.length) return 0;

    return Math.round(
      scores.reduce(
        (sum, score) => sum + score,
        0
      ) / scores.length
    );
  }, [compliance, frameworkCards]);

  const selectedFrameworkData = useMemo(() => {
    if (selectedFramework === FRAMEWORKS.ALL) {
      const controls = frameworkCards.flatMap(
        (framework) =>
          framework.controls.map((control) => ({
            ...control,
            framework:
              framework.framework,
          }))
      );

      return {
        controls,
        score: overallScore,
        total: controls.length,
        passed: controls.filter(
          (item) => item.status === "PASSED"
        ).length,
        failed: controls.filter(
          (item) => item.status === "FAILED"
        ).length,
        review: controls.filter(
          (item) => item.status === "REVIEW"
        ).length,
      };
    }

    const framework = frameworkCards.find(
      (item) =>
        item.framework === selectedFramework
    );

    return (
      framework || {
        controls: [],
        score: 0,
        total: 0,
        passed: 0,
        failed: 0,
        review: 0,
      }
    );
  }, [
    selectedFramework,
    frameworkCards,
    overallScore,
  ]);

  const controls = selectedFrameworkData.controls;

  const globalSummary = useMemo(() => {
    const dashboardControls =
      compliance?.controls || {};

    return {
      total:
        Number(
          dashboardControls.total ??
            compliance?.total_controls
        ) ||
        frameworkCards.reduce(
          (sum, item) => sum + item.total,
          0
        ),

      passed:
        Number(
          dashboardControls.passed ??
            compliance?.passed_controls
        ) ||
        frameworkCards.reduce(
          (sum, item) => sum + item.passed,
          0
        ),

      failed:
        Number(
          dashboardControls.failed ??
            compliance?.failed_controls
        ) ||
        frameworkCards.reduce(
          (sum, item) => sum + item.failed,
          0
        ),

      review:
        Number(
          dashboardControls.review ??
            compliance?.review_controls
        ) ||
        frameworkCards.reduce(
          (sum, item) => sum + item.review,
          0
        ),
    };
  }, [compliance, frameworkCards]);

  const accountName =
    dashboard?.account_name ||
    dashboard?.account ||
    dashboard?.aws_account_id ||
    latest?.account_name ||
    latest?.aws_account_id ||
    "AWS Account";

  const awsAccountId =
    dashboard?.aws_account_id ||
    latest?.aws_account_id ||
    dashboard?.account ||
    "—";

  const scanId =
    dashboard?.scan_id ||
    latest?.scan_id ||
    "—";

  const scanTime =
    dashboard?.scan_time ||
    dashboard?.evaluated_at ||
    latest?.evaluated_at ||
    latest?.created_at;

  const complianceStatus =
    compliance?.status ||
    (overallScore >= 80
      ? "COMPLIANT"
      : "NON_COMPLIANT");

  const trendPoints = useMemo(() => {
    return [...trend]
      .filter((item) => item)
      .sort((a, b) => {
        const dateA = new Date(
          a.evaluated_at ||
            a.scan_time ||
            a.created_at ||
            a.timestamp ||
            0
        ).getTime();

        const dateB = new Date(
          b.evaluated_at ||
            b.scan_time ||
            b.created_at ||
            b.timestamp ||
            0
        ).getTime();

        return dateA - dateB;
      })
      .slice(-12)
      .map((item) => ({
        score: Number(
          item.compliance_score ??
            item.score ??
            0
        ),
        date:
          item.evaluated_at ||
          item.scan_time ||
          item.created_at ||
          item.timestamp,
        framework:
          item.framework ||
          selectedFramework,
      }));
  }, [trend, selectedFramework]);

  const trendMin = trendPoints.length
    ? Math.min(
        ...trendPoints.map((item) => item.score)
      )
    : 0;

  const trendMax = trendPoints.length
    ? Math.max(
        ...trendPoints.map((item) => item.score)
      )
    : 100;

  const trendRange = Math.max(
    20,
    trendMax - trendMin
  );

  const getTrendY = (score) => {
    if (!trendPoints.length) return 50;

    return (
      90 -
      ((score - trendMin) / trendRange) * 70
    );
  };

  const getTrendX = (index) => {
    if (trendPoints.length <= 1) return 50;

    return (
      5 +
      (index / (trendPoints.length - 1)) * 90
    );
  };

  const trendPolyline = trendPoints
    .map(
      (point, index) =>
        `${getTrendX(index)},${getTrendY(
          point.score
        )}`
    )
    .join(" ");

  const frameworkHistory = useMemo(() => {
    return history
      .filter((item) => {
        if (
          selectedFramework === FRAMEWORKS.ALL
        ) {
          return true;
        }

        return (
          item.framework === selectedFramework
        );
      })
      .slice(0, 8);
  }, [history, selectedFramework]);

  const handleControlClick = (control) => {
    setSelectedControl(control);
  };

  const closeControl = () => {
    setSelectedControl(null);
  };

  if (loading) {
    return (
      <div className="compliance-page">
        <div className="compliance-loading">
          <div className="compliance-loading-spinner" />
          <h2>Loading Compliance Center</h2>
          <p>
            Evaluating your latest security posture
            and compliance data...
          </p>
        </div>
      </div>
    );
  }

  return (
    <div className="compliance-page">
      <header className="compliance-header">
        <div className="compliance-header-content">
          <div>
            <div className="compliance-breadcrumb">
              Security
              <span>/</span>
              Compliance
            </div>

            <h1>Compliance Center</h1>

            <p>
              Measure your AWS security posture
              against configured compliance
              frameworks.
            </p>
          </div>

          <div className="compliance-header-actions">
            <div className="assessment-meta">
              <span className="assessment-label">
                Latest assessment
              </span>
              <strong>
                {formatDate(scanTime)}
              </strong>
            </div>

            <button
              type="button"
              className="refresh-button"
              onClick={() =>
                fetchComplianceData(true)
              }
              disabled={refreshing}
            >
              <span
                className={
                  refreshing
                    ? "refresh-icon spinning"
                    : "refresh-icon"
                }
              >
                ↻
              </span>

              {refreshing
                ? "Refreshing..."
                : "Refresh"}
            </button>
          </div>
        </div>
      </header>

      {error && (
        <div className="compliance-alert error">
          <div className="alert-icon">!</div>

          <div>
            <strong>
              Some compliance data could not be
              loaded
            </strong>
            <p>{error}</p>
          </div>

          <button
            type="button"
            onClick={() =>
              fetchComplianceData(true)
            }
          >
            Retry
          </button>
        </div>
      )}

      <section className="compliance-account-bar">
        <div className="account-context">
          <div className="account-icon">AWS</div>

          <div>
            <span>Monitored account</span>
            <strong>{accountName}</strong>
          </div>
        </div>

        <div className="account-details">
          <div>
            <span>AWS Account ID</span>
            <strong>{awsAccountId}</strong>
          </div>

          <div>
            <span>Scan ID</span>
            <strong title={scanId}>
              {scanId === "—"
                ? "—"
                : `${scanId.slice(0, 8)}...`}
            </strong>
          </div>

          <div>
            <span>Assessment status</span>
            <strong
              className={`inline-status ${getStatusClass(
                complianceStatus
              )}`}
            >
              <span />
              {String(complianceStatus)
                .replaceAll("_", " ")}
            </strong>
          </div>
        </div>
      </section>

      <section className="compliance-overview-grid">
        <div className="overall-score-card">
          <div className="score-card-header">
            <div>
              <span className="section-eyebrow">
                Overall posture
              </span>
              <h2>Compliance Score</h2>
            </div>

            <span
              className={`score-status ${getScoreClass(
                overallScore
              )}`}
            >
              {overallScore >= 90
                ? "Excellent"
                : overallScore >= 75
                ? "Good"
                : overallScore >= 50
                ? "Needs Attention"
                : "Critical"}
            </span>
          </div>

          <div className="overall-score-content">
            <ScoreRing score={overallScore} />

            <div className="score-explanation">
              <h3>
                {overallScore >= 80
                  ? "Your posture is relatively strong."
                  : "Your environment needs attention."}
              </h3>

              <p>
                This score reflects the compliance
                assessment generated from your latest
                AWS security scan.
              </p>

              <div className="score-stats">
                <div>
                  <strong>
                    {globalSummary.total}
                  </strong>
                  <span>Total Controls</span>
                </div>

                <div>
                  <strong className="text-passed">
                    {globalSummary.passed}
                  </strong>
                  <span>Passed</span>
                </div>

                <div>
                  <strong className="text-failed">
                    {globalSummary.failed}
                  </strong>
                  <span>Failed</span>
                </div>

                <div>
                  <strong className="text-review">
                    {globalSummary.review}
                  </strong>
                  <span>Review</span>
                </div>
              </div>
            </div>
          </div>
        </div>

        <div className="framework-overview-card">
          <div className="section-card-header">
            <div>
              <span className="section-eyebrow">
                Framework coverage
              </span>
              <h2>Security Standards</h2>
            </div>
          </div>

          <div className="framework-mini-list">
            {frameworkCards.map((item) => (
              <button
                type="button"
                key={item.framework}
                className="framework-mini-item"
                onClick={() =>
                  setSelectedFramework(
                    item.framework
                  )
                }
              >
                <div className="framework-mini-info">
                  <strong>
                    {formatFramework(
                      item.framework
                    )}
                  </strong>
                  <span>
                    {item.passed} passed ·{" "}
                    {item.failed} failed ·{" "}
                    {item.review} review
                  </span>
                </div>

                <div
                  className={`framework-mini-score ${getScoreClass(
                    item.score
                  )}`}
                >
                  {item.score}%
                </div>
              </button>
            ))}
          </div>
        </div>
      </section>

      <section className="framework-selector-section">
        <div className="section-heading-row">
          <div>
            <span className="section-eyebrow">
              Compliance frameworks
            </span>
            <h2>Choose a framework</h2>
          </div>

          <span className="control-count">
            {selectedFrameworkData.controls.length}{" "}
            controls shown
          </span>
        </div>

        <div className="framework-selector">
          <button
            type="button"
            className={
              selectedFramework === FRAMEWORKS.ALL
                ? "active"
                : ""
            }
            onClick={() =>
              setSelectedFramework(
                FRAMEWORKS.ALL
              )
            }
          >
            All Frameworks
          </button>

          {frameworkCards.map((item) => (
            <button
              type="button"
              key={item.framework}
              className={
                selectedFramework ===
                item.framework
                  ? "active"
                  : ""
              }
              onClick={() =>
                setSelectedFramework(
                  item.framework
                )
              }
            >
              {formatFramework(item.framework)}
            </button>
          ))}
        </div>
      </section>

      <section className="compliance-content-grid">
        <div className="controls-card">
          <div className="section-card-header">
            <div>
              <span className="section-eyebrow">
                Control assessment
              </span>

              <h2>
                {selectedFramework ===
                FRAMEWORKS.ALL
                  ? "All Controls"
                  : formatFramework(
                      selectedFramework
                    )}
              </h2>
            </div>

            <div className="control-summary-pills">
              <span className="summary-pill passed">
                ✓ {selectedFrameworkData.passed}
              </span>

              <span className="summary-pill failed">
                ! {selectedFrameworkData.failed}
              </span>

              <span className="summary-pill review">
                ? {selectedFrameworkData.review}
              </span>
            </div>
          </div>

          {controls.length === 0 ? (
            <div className="compliance-empty">
              <div className="empty-icon">✓</div>
              <h3>No controls available</h3>
              <p>
                Run a completed AWS security scan
                to populate compliance controls.
              </p>
            </div>
          ) : (
            <div className="controls-table-wrapper">
              <table className="controls-table">
                <thead>
                  <tr>
                    <th>Control</th>
                    <th>Framework</th>
                    <th>Service</th>
                    <th>Status</th>
                    <th>Resource</th>
                    <th />
                  </tr>
                </thead>

                <tbody>
                  {controls.map(
                    (control, index) => {
                      const status =
                        STATUS_CONFIG[
                          control.status
                        ] ||
                        STATUS_CONFIG.REVIEW;

                      return (
                        <tr
                          key={`${control.id}-${index}`}
                          onClick={() =>
                            handleControlClick(
                              control
                            )
                          }
                        >
                          <td>
                            <div className="control-name">
                              <strong>
                                {control.id}
                              </strong>

                              <span>
                                {control.name}
                              </span>
                            </div>
                          </td>

                          <td>
                            {control.framework
                              ? formatFramework(
                                  control.framework
                                )
                              : selectedFramework ===
                                FRAMEWORKS.ALL
                              ? "Multiple"
                              : formatFramework(
                                  selectedFramework
                                )}
                          </td>

                          <td>
                            <span className="service-badge">
                              {control.service ||
                                "AWS"}
                            </span>
                          </td>

                          <td>
                            <span
                              className={`control-status ${status.className}`}
                            >
                              <span>
                                {control.status ===
                                "PASSED"
                                  ? "✓"
                                  : control.status ===
                                    "FAILED"
                                  ? "!"
                                  : "?"}
                              </span>
                              {status.label}
                            </span>
                          </td>

                          <td>
                            <span
                              className="resource-cell"
                              title={
                                control.resource ||
                                ""
                              }
                            >
                              {control.resource ||
                                "—"}
                            </span>
                          </td>

                          <td>
                            <button
                              type="button"
                              className="view-control-button"
                              onClick={(event) => {
                                event.stopPropagation();
                                handleControlClick(
                                  control
                                );
                              }}
                            >
                              View
                            </button>
                          </td>
                        </tr>
                      );
                    }
                  )}
                </tbody>
              </table>
            </div>
          )}
        </div>

        <aside className="compliance-side-column">
          <div className="trend-card">
            <div className="section-card-header">
              <div>
                <span className="section-eyebrow">
                  Historical posture
                </span>
                <h2>Compliance Trend</h2>
              </div>
            </div>

            {trendPoints.length === 0 ? (
              <div className="small-empty">
                <span>—</span>
                <p>
                  Trend data will appear after
                  compliance assessments are stored.
                </p>
              </div>
            ) : (
              <>
                <div className="trend-chart">
                  <div className="trend-y-axis">
                    <span>
                      {Math.round(
                        Math.min(100, trendMax)
                      )}
                      %
                    </span>
                    <span>
                      {Math.round(
                        (trendMax + trendMin) / 2
                      )}
                      %
                    </span>
                    <span>
                      {Math.round(
                        Math.max(0, trendMin)
                      )}
                      %
                    </span>
                  </div>

                  <svg
                    viewBox="0 0 100 100"
                    preserveAspectRatio="none"
                    className="trend-svg"
                    aria-label="Compliance score trend"
                  >
                    <line
                      x1="5"
                      y1="20"
                      x2="95"
                      y2="20"
                      className="trend-grid-line"
                    />
                    <line
                      x1="5"
                      y1="55"
                      x2="95"
                      y2="55"
                      className="trend-grid-line"
                    />
                    <line
                      x1="5"
                      y1="90"
                      x2="95"
                      y2="90"
                      className="trend-grid-line"
                    />

                    <polyline
                      points={trendPolyline}
                      fill="none"
                      className="trend-line"
                    />

                    {trendPoints.map(
                      (point, index) => (
                        <circle
                          key={`${point.date}-${index}`}
                          cx={getTrendX(index)}
                          cy={getTrendY(
                            point.score
                          )}
                          r="1.8"
                          className="trend-point"
                        />
                      )
                    )}
                  </svg>
                </div>

                <div className="trend-labels">
                  {trendPoints.map(
                    (point, index) => (
                      <span
                        key={`${point.date}-label-${index}`}
                      >
                        {point.date
                          ? new Date(
                              point.date
                            ).toLocaleDateString(
                              undefined,
                              {
                                month: "short",
                                day: "numeric",
                              }
                            )
                          : "—"}
                      </span>
                    )
                  )}
                </div>
              </>
            )}
          </div>

          <div className="history-card">
            <div className="section-card-header">
              <div>
                <span className="section-eyebrow">
                  Assessment history
                </span>
                <h2>Recent Assessments</h2>
              </div>
            </div>

            {frameworkHistory.length === 0 ? (
              <div className="small-empty">
                <span>◷</span>
                <p>
                  No compliance history is
                  available yet.
                </p>
              </div>
            ) : (
              <div className="history-list">
                {frameworkHistory.map(
                  (item, index) => {
                    const score = Number(
                      item.compliance_score ??
                        item.score ??
                        0
                    );

                    return (
                      <div
                        className="history-item"
                        key={
                          item._id ||
                          `${item.framework}-${item.scan_id}-${index}`
                        }
                      >
                        <div className="history-item-icon">
                          {formatFramework(
                            item.framework
                          )
                            .split(" ")
                            .map((word) =>
                              word[0]
                            )
                            .slice(0, 2)
                            .join("")}
                        </div>

                        <div className="history-item-content">
                          <strong>
                            {formatFramework(
                              item.framework
                            )}
                          </strong>

                          <span>
                            {formatDate(
                              item.evaluated_at ||
                                item.created_at
                            )}
                          </span>
                        </div>

                        <div
                          className={`history-score ${getScoreClass(
                            score
                          )}`}
                        >
                          {score}%
                        </div>
                      </div>
                    );
                  }
                )}
              </div>
            )}
          </div>

          {statistics && (
            <div className="statistics-card">
              <div className="section-card-header">
                <div>
                  <span className="section-eyebrow">
                    Security analytics
                  </span>
                  <h2>Assessment Statistics</h2>
                </div>
              </div>

              <div className="statistics-grid">
                {Object.entries(statistics)
                  .filter(
                    ([, value]) =>
                      typeof value ===
                        "number" ||
                      typeof value ===
                        "string"
                  )
                  .slice(0, 4)
                  .map(([key, value]) => (
                    <div
                      className="statistic-item"
                      key={key}
                    >
                      <strong>{value}</strong>
                      <span>
                        {key
                          .replaceAll("_", " ")
                          .replace(/\b\w/g, (l) =>
                            l.toUpperCase()
                          )}
                      </span>
                    </div>
                  ))}
              </div>
            </div>
          )}
        </aside>
      </section>

      <div className="compliance-disclaimer">
        <div className="disclaimer-icon">i</div>

        <div>
          <strong>Compliance assessment</strong>
          <p>
            CloudGuardAI evaluates your AWS security
            findings against the configured internal
            framework mappings. Validate framework
            versions and control mappings with your
            compliance or security team before using
            these results as formal compliance
            certification.
          </p>
        </div>
      </div>

      {selectedControl && (
        <div
          className="control-modal-backdrop"
          onClick={closeControl}
          role="presentation"
        >
          <div
            className="control-modal"
            onClick={(event) =>
              event.stopPropagation()
            }
            role="dialog"
            aria-modal="true"
            aria-label="Compliance control details"
          >
            <div className="control-modal-header">
              <div>
                <span className="section-eyebrow">
                  Control details
                </span>

                <h2>
                  {selectedControl.id}
                </h2>
              </div>

              <button
                type="button"
                className="modal-close"
                onClick={closeControl}
                aria-label="Close control details"
              >
                ×
              </button>
            </div>

            <div className="control-modal-body">
              <div className="modal-control-title">
                <span
                  className={`control-status ${
                    STATUS_CONFIG[
                      selectedControl.status
                    ]?.className ||
                    "review"
                  }`}
                >
                  {selectedControl.status ===
                  "PASSED"
                    ? "✓ Passed"
                    : selectedControl.status ===
                      "FAILED"
                    ? "! Failed"
                    : "? Review"}
                </span>

                <h3>
                  {selectedControl.name}
                </h3>
              </div>

              <div className="modal-detail-grid">
                <div>
                  <span>Framework</span>
                  <strong>
                    {selectedControl.framework
                      ? formatFramework(
                          selectedControl.framework
                        )
                      : formatFramework(
                          selectedFramework
                        )}
                  </strong>
                </div>

                <div>
                  <span>Service</span>
                  <strong>
                    {selectedControl.service ||
                      "AWS"}
                  </strong>
                </div>

                <div>
                  <span>Finding ID</span>
                  <strong>
                    {selectedControl.findingId ||
                      "—"}
                  </strong>
                </div>

                <div>
                  <span>Resource</span>
                  <strong className="breakable">
                    {selectedControl.resource ||
                      "—"}
                  </strong>
                </div>
              </div>

              <div className="modal-section">
                <h4>Description</h4>
                <p>
                  {selectedControl.description}
                </p>
              </div>

              <div className="modal-section">
                <h4>Evidence</h4>

                {selectedControl.evidence &&
                Object.keys(
                  selectedControl.evidence
                ).length > 0 ? (
                  <pre className="evidence-block">
                    {JSON.stringify(
                      selectedControl.evidence,
                      null,
                      2
                    )}
                  </pre>
                ) : (
                  <div className="no-evidence">
                    Evidence was not provided by
                    the latest scan for this
                    control.
                  </div>
                )}
              </div>
            </div>

            <div className="control-modal-footer">
              <button
                type="button"
                className="secondary-button"
                onClick={closeControl}
              >
                Close
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}

export default Compliance;