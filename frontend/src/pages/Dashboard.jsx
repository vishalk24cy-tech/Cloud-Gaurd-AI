import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import { Link, useNavigate } from "react-router-dom";
import {
  Activity,
  ArrowRight,
  Boxes,
  Bot,
  CheckCircle2,
  ClipboardCheck,
  Cloud,
  Gauge,
  Plus,
  ShieldAlert,
} from "lucide-react";
import {
  Bar,
  BarChart,
  CartesianGrid,
  Line,
  LineChart,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis,
} from "recharts";

import api from "../services/api";
import EnterpriseHeader from "../components/EnterpriseHeader";
import AWSAccountCard from "../components/AWSAccountCard";
import QuickActions from "../components/QuickActions";
import AIChatWidget from "../components/AIChatWidget";

import "./dashboard.css";

const SEVERITY_SERIES = [
  { key: "CRITICAL", label: "Critical", color: "#fb5262" },
  { key: "HIGH", label: "High", color: "#f28b3c" },
  { key: "MEDIUM", label: "Medium", color: "#e8bd4d" },
  { key: "LOW", label: "Low", color: "#48aef2" },
];

function normalizeHistory(data) {
  if (Array.isArray(data)) return data;
  if (Array.isArray(data?.scans)) return data.scans;
  if (Array.isArray(data?.history)) return data.history;
  if (Array.isArray(data?.data)) return data.data;
  return [];
}

function getScanFindings(scan) {
  const findings =
    scan?.findings ??
    scan?.scan?.findings ??
    scan?.result?.findings;

  return Array.isArray(findings) ? findings : null;
}

function getScanTimestamp(scan) {
  return scan?.scan_time ?? scan?.created_at ?? scan?.timestamp;
}

function getFindingsTrend(history, days) {
  const cutoff = Date.now() - days * 24 * 60 * 60 * 1000;

  return history
    .map((scan) => {
      const timestamp = getScanTimestamp(scan);
      const time = timestamp ? new Date(timestamp).getTime() : NaN;
      const findings = getScanFindings(scan);

      if (
        !Number.isFinite(time) ||
        time < cutoff ||
        time > Date.now() ||
        !findings
      ) {
        return null;
      }

      const counts = Object.fromEntries(
        SEVERITY_SERIES.map(({ key }) => [key, 0])
      );

      findings.forEach((finding) => {
        const severity = String(
          finding?.severity || ""
        ).toUpperCase();

        if (Object.hasOwn(counts, severity)) {
          counts[severity] += 1;
        }
      });

      return {
        date: new Date(time).toLocaleDateString(undefined, {
          month: "short",
          day: "numeric",
        }),
        timestamp: time,
        ...counts,
      };
    })
    .filter(Boolean)
    .sort((a, b) => a.timestamp - b.timestamp);
}

function getResourceCounts(dashboard, latestScan) {
  const resources =
    dashboard?.resource_distribution ??
    dashboard?.resources ??
    latestScan?.resources;

  if (!resources || typeof resources !== "object") return [];

  const services = [
    ["EC2", "ec2"],
    ["S3", "s3"],
    ["IAM", "iam"],
    ["RDS", "rds"],
    ["Lambda", "lambda"],
    ["Other", "other"],
  ];

  return services.flatMap(([name, key]) => {
    const value =
      resources[key] ??
      resources[name] ??
      resources[name.toUpperCase()];

    if (
      value === undefined ||
      value === null ||
      !Number.isFinite(Number(value))
    ) {
      return [];
    }

    return [{ name, value: Number(value) }];
  });
}

function getService(finding) {
  if (finding?.service || finding?.resource_type) {
    return String(
      finding.service || finding.resource_type
    ).toUpperCase();
  }

  if (finding?.bucket) return "S3";
  if (finding?.security_group || finding?.instance) return "EC2";
  if (finding?.user) return "IAM";
  if (finding?.database) return "RDS";
  if (finding?.function) return "LAMBDA";

  return "—";
}

function getResource(finding) {
  return (
    finding?.resource ||
    finding?.bucket ||
    finding?.security_group ||
    finding?.instance ||
    finding?.user ||
    finding?.database ||
    finding?.function ||
    "—"
  );
}

function formatAge(value) {
  if (!value) return "—";

  const timestamp = new Date(value).getTime();

  if (!Number.isFinite(timestamp)) return "—";

  const minutes = Math.max(
    0,
    Math.floor((Date.now() - timestamp) / 60000)
  );

  if (minutes < 60) return `${minutes}m ago`;

  const hours = Math.floor(minutes / 60);

  if (hours < 24) return `${hours}h ago`;

  const days = Math.floor(hours / 24);

  if (days < 30) return `${days}d ago`;

  return new Date(timestamp).toLocaleDateString();
}

function maskAccountId(value) {
  if (!value) return "—";

  const digits = String(value).replace(/\D/g, "");

  if (digits.length <= 4) return value;

  return `•••• •••• ${digits.slice(-4)}`;
}

function Dashboard() {
  const navigate = useNavigate();

  const [dashboard, setDashboard] = useState(null);
  const [history, setHistory] = useState([]);
  const [findings, setFindings] = useState([]);
  const [accounts, setAccounts] = useState(null);
  const [aiAnalysis, setAiAnalysis] = useState(null);
  const [loading, setLoading] = useState(true);
  const [dashboardError, setDashboardError] = useState(false);
  const [trendRange, setTrendRange] = useState(30);
  const [showAccountManager, setShowAccountManager] = useState(false);

  const loadingRef = useRef(false);

  const loadDashboard = useCallback(async () => {
    if (loadingRef.current) return;

    loadingRef.current = true;

    try {
      setDashboardError(false);

      const dashboardResponse = await api.get("/dashboard/");
      const historyResponse = await api.get("/cloud/history");
      const accountsResponse = await api.get("/aws/accounts");

      const historyData = normalizeHistory(historyResponse.data);

      const accountData = Array.isArray(
        accountsResponse.data?.accounts
      )
        ? accountsResponse.data.accounts
        : [];

      let latestScan = historyData[0];

      if (latestScan && (!getScanFindings(latestScan) || getScanFindings(latestScan).length === 0) && (latestScan._id || latestScan.id)) {
        try {
          const scanId = latestScan._id || latestScan.id;
          const detailRes = await api.get(`/cloud/history/${scanId}`);
          const detailedScan = detailRes.data?.scan || detailRes.data?.data || detailRes.data;
          if (detailedScan) {
            latestScan = { ...latestScan, ...detailedScan };
            historyData[0] = latestScan;
          }
        } catch (detailErr) {
          console.warn("Could not load full scan details for dashboard:", detailErr);
        }
      }

      setDashboard(dashboardResponse.data);
      setHistory(historyData);
      setFindings(getScanFindings(latestScan) || []);
      setAiAnalysis(latestScan?.gemini_analysis || null);
      setAccounts(accountData);

      window.dispatchEvent(
        new Event("aws-account-status-updated")
      );
    } catch (error) {
      console.error("Dashboard Error:", error);
      setDashboardError(true);
    } finally {
      loadingRef.current = false;
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    void loadDashboard();
  }, [loadDashboard]);

  const latestScan = history[0];

  const latestScanTimestamp =
    getScanTimestamp(latestScan);

  const hasScanData = history.length > 0;

  const trendData = useMemo(
    () => getFindingsTrend(history, trendRange),
    [history, trendRange]
  );

  const resourceData = useMemo(
    () => getResourceCounts(dashboard, latestScan),
    [dashboard, latestScan]
  );

  const recommendations = Array.isArray(
    aiAnalysis?.recommendations
  )
    ? aiAnalysis.recommendations.slice(0, 4)
    : [];

  const connectedAccount = Array.isArray(accounts)
    ? accounts[0]
    : null;

  // Only show real metric values when an account is connected AND scan data exists
  const hasAccountAndScan =
    connectedAccount != null && hasScanData;

  const totalFindings = hasAccountAndScan
    ? (
        dashboard?.total_findings ??
        dashboard?.findings_count ??
        findings.length
      )
    : "—";

  const protectedResources = hasAccountAndScan
    ? (
        dashboard?.protected_resources ??
        dashboard?.total_resources ??
        "—"
      )
    : "—";

  const rawComplianceScore = hasAccountAndScan
    ? (
        dashboard?.compliance_score ??
        dashboard?.compliance ??
        null
      )
    : null;

  const complianceScore = rawComplianceScore;

  /*
   * SECURITY SCORE
   *
   * First use dashboard.security_score.
   * If that is not available, use the latest scan's risk_score.
   *
   * Your completed scan is returning:
   * risk_score = 64.29
   */
  const securityScore = hasAccountAndScan
    ? (
        dashboard?.security_score ??
        latestScan?.risk_score ??
        "—"
      )
    : "—";

  const hasSecurityScore =
    hasAccountAndScan &&
    (
      dashboard?.security_score != null ||
      latestScan?.risk_score != null
    );

  if (loading) {
    return (
      <div
        className="dashboard-loading"
        role="status"
        aria-live="polite"
      >
        <div className="loading-ring" />
        <p>Loading security operations data...</p>
      </div>
    );
  }

  if (dashboardError && !dashboard) {
    return (
      <div
        className="dashboard-error-state"
        role="alert"
      >
        <div className="error-state-mark">!</div>

        <h2>
          Security operations data is unavailable
        </h2>

        <p>
          We could not load the latest cloud posture.
          Try again to reconnect to the security workspace.
        </p>

        <button
          type="button"
          className="scan-button"
          onClick={loadDashboard}
        >
          Try again
        </button>
      </div>
    );
  }

  return (
    <div className="ops-dashboard">

      <EnterpriseHeader
        onRefresh={loadDashboard}
        awsConnected={
          accounts === null
            ? null
            : accounts.length > 0
        }
        lastScan={
          latestScanTimestamp
            ? new Date(
                latestScanTimestamp
              ).toLocaleString()
            : "Never"
        }
      />

      <section
        className="ops-aws-panel"
        aria-label="AWS connection status"
      >
        <div className="ops-aws-mark">
          <Cloud size={19} aria-hidden="true" />
        </div>

        <div className="ops-aws-copy">
          <span className="ops-eyebrow">
            AWS ENVIRONMENT
          </span>

          <strong>
            {accounts === null
              ? "Checking AWS connection"
              : connectedAccount
                ? "Connected AWS account"
                : "No AWS account connected"}
          </strong>

          <span>
            {connectedAccount?.account_name ||
              (
                connectedAccount
                  ? "Production account"
                  : "Connect an AWS environment to start security scanning."
              )}
          </span>
        </div>

        <div
          className={`ops-connection-state ${
            connectedAccount
              ? "is-connected"
              : accounts === null
                ? "is-pending"
                : "is-disconnected"
          }`}
        >
          <span className="ops-state-dot" />

          {accounts === null
            ? "Checking"
            : connectedAccount
              ? "Connected"
              : "Not connected"}
        </div>

        {connectedAccount && (
          <div className="ops-account-meta">
            <span>
              Account{" "}
              <strong>
                {maskAccountId(
                  connectedAccount.aws_account_id
                )}
              </strong>
            </span>

            <span>
              Region{" "}
              <strong>
                {connectedAccount.region || "—"}
              </strong>
            </span>
          </div>
        )}

        <button
          type="button"
          className="ops-outline-button"
          onClick={() =>
            connectedAccount
              ? setShowAccountManager(
                  (shown) => !shown
                )
              : navigate("/connect-aws")
          }
        >
          {connectedAccount
            ? (
                showAccountManager
                  ? "Close account manager"
                  : "Manage accounts"
              )
            : "Connect AWS account"}
        </button>
      </section>

      {showAccountManager && (
        <div className="ops-account-manager">
          <AWSAccountCard
            accounts={accounts || []}
            onRefresh={loadDashboard}
          />
        </div>
      )}

      <section
        className="ops-metrics"
        aria-label="Key security metrics"
      >

        {/* SECURITY SCORE */}
        <MetricCard
          icon={Gauge}
          title="Security score"
          value={securityScore}
          suffix={
            hasSecurityScore
              ? "/ 100"
              : ""
          }
          note={
            !connectedAccount
              ? "Connect AWS to begin"
              : hasScanData
                ? "Latest completed scan"
                : "Run a scan to see score"
          }
          color="blue"
        />

        {/* SECURITY FINDINGS */}
        <MetricCard
          icon={ShieldAlert}
          title="Security findings"
          value={totalFindings}
          note={
            !connectedAccount
              ? "Connect AWS to begin"
              : hasScanData
                ? "Latest scan findings"
                : "Run a scan to see findings"
          }
          color="red"
        />

        {/* PROTECTED RESOURCES */}
        <MetricCard
          icon={Boxes}
          title="Protected resources"
          value={protectedResources}
          note={
            !connectedAccount
              ? "Connect AWS to begin"
              : hasScanData
                ? "Discovered in AWS"
                : "Run a scan to discover resources"
          }
          color="cyan"
        />

        {/* COMPLIANCE */}
        <MetricCard
          icon={ClipboardCheck}
          title="Compliance"
          value={
            complianceScore == null
              ? "—"
              : complianceScore
          }
          suffix={
            complianceScore == null
              ? ""
              : "%"
          }
          note={
            !connectedAccount
              ? "Connect AWS to begin"
              : hasScanData
                ? "Latest compliance score"
                : "Run a scan to see compliance"
          }
          color="purple"
        />

      </section>

      <section
        className="ops-chart-grid"
        aria-label="Security analytics"
      >

        {/* FINDINGS TREND */}
        <article className="ops-panel ops-chart-panel">

          <div className="ops-panel-heading">
            <div>
              <span className="ops-eyebrow">
                SCAN ANALYTICS
              </span>

              <h2>
                Security findings trend
              </h2>
            </div>

            <label className="ops-range-control">
              <span className="visually-hidden">
                Trend period
              </span>

              <select
                value={trendRange}
                onChange={(event) =>
                  setTrendRange(
                    Number(event.target.value)
                  )
                }
              >
                <option value={7}>
                  Last 7 days
                </option>

                <option value={30}>
                  Last 30 days
                </option>

                <option value={90}>
                  Last 90 days
                </option>
              </select>
            </label>
          </div>

          <div className="ops-chart-legend">
            {SEVERITY_SERIES.map((item) => (
              <span key={item.key}>
                <i
                  style={{
                    background: item.color,
                  }}
                />

                {item.label}
              </span>
            ))}
          </div>

          {trendData.length ? (
            <div className="ops-chart-canvas">
              <ResponsiveContainer
                width="100%"
                height="100%"
              >
                <LineChart
                  data={trendData}
                  margin={{
                    top: 8,
                    right: 14,
                    bottom: 0,
                    left: -20,
                  }}
                >
                  <CartesianGrid
                    stroke="#1a2c3b"
                    strokeDasharray="3 5"
                    vertical={false}
                  />

                  <XAxis
                    dataKey="date"
                    tick={{
                      fill: "#8ca0b2",
                      fontSize: 11,
                    }}
                    axisLine={false}
                    tickLine={false}
                  />

                  <YAxis
                    allowDecimals={false}
                    tick={{
                      fill: "#8ca0b2",
                      fontSize: 11,
                    }}
                    axisLine={false}
                    tickLine={false}
                  />

                  <Tooltip
                    contentStyle={{
                      background: "#0b1722",
                      border:
                        "1px solid #263b4c",
                      borderRadius: 8,
                      color: "#e8f0f6",
                    }}
                  />

                  {SEVERITY_SERIES.map(
                    (item) => (
                      <Line
                        key={item.key}
                        type="monotone"
                        dataKey={item.key}
                        name={item.label}
                        stroke={item.color}
                        strokeWidth={2}
                        dot={false}
                        activeDot={{ r: 4 }}
                      />
                    )
                  )}
                </LineChart>
              </ResponsiveContainer>
            </div>
          ) : (
            <EmptyChart
              message={
                "No dated severity data is available for this period."
              }
            />
          )}
        </article>

        {/* AWS INVENTORY */}
        <article className="ops-panel ops-chart-panel">

          <div className="ops-panel-heading">
            <div>
              <span className="ops-eyebrow">
                AWS INVENTORY
              </span>

              <h2>
                Resource security posture
              </h2>
            </div>

            <span className="ops-chart-caption">
              Latest scan
            </span>
          </div>

          {resourceData.length ? (
            <div className="ops-chart-canvas">
              <ResponsiveContainer
                width="100%"
                height="100%"
              >
                <BarChart
                  data={resourceData}
                  margin={{
                    top: 8,
                    right: 10,
                    bottom: 0,
                    left: -20,
                  }}
                >
                  <CartesianGrid
                    stroke="#1a2c3b"
                    strokeDasharray="3 5"
                    vertical={false}
                  />

                  <XAxis
                    dataKey="name"
                    tick={{
                      fill: "#8ca0b2",
                      fontSize: 11,
                    }}
                    axisLine={false}
                    tickLine={false}
                  />

                  <YAxis
                    allowDecimals={false}
                    tick={{
                      fill: "#8ca0b2",
                      fontSize: 11,
                    }}
                    axisLine={false}
                    tickLine={false}
                  />

                  <Tooltip
                    contentStyle={{
                      background: "#0b1722",
                      border:
                        "1px solid #263b4c",
                      borderRadius: 8,
                      color: "#e8f0f6",
                    }}
                  />

                  <Bar
                    dataKey="value"
                    name="Resources"
                    fill="#28b8ef"
                    radius={[
                      4,
                      4,
                      0,
                      0,
                    ]}
                    maxBarSize={34}
                  />
                </BarChart>
              </ResponsiveContainer>
            </div>
          ) : (
            <EmptyChart
              message={
                "Resource inventory will appear after a scan reports service counts."
              }
            />
          )}
        </article>

      </section>

      <section className="ops-detail-grid">

        {/* LATEST FINDINGS */}
        <article className="ops-panel ops-findings-panel">

          <div className="ops-panel-heading">
            <div>
              <span className="ops-eyebrow">
                LATEST SCAN
              </span>

              <h2>
                Recent security findings
              </h2>
            </div>

            <Link
              className="ops-text-link"
              to="/findings"
            >
              View all{" "}
              <ArrowRight size={14} />
            </Link>
          </div>

          {findings.length ? (
            <div className="ops-table-scroll">

              <table className="ops-findings-table">

                <thead>
                  <tr>
                    <th>Severity</th>
                    <th>Finding</th>
                    <th>Resource</th>
                    <th>Service</th>
                    <th>Detected</th>
                  </tr>
                </thead>

                <tbody>
                  {findings
                    .slice(0, 6)
                    .map((finding, index) => {
                      const severity =
                        String(
                          finding?.severity ||
                            "UNKNOWN"
                        ).toUpperCase();

                      return (
                        <tr
                          key={
                            finding?.finding_id ||
                            finding?._id ||
                            `${getResource(
                              finding
                            )}-${index}`
                          }
                        >
                          <td>
                            <span
                              className={`ops-severity is-${severity.toLowerCase()}`}
                            >
                              {severity}
                            </span>
                          </td>

                          <td className="ops-finding-title">
                            {finding?.issue ||
                              finding?.title ||
                              finding?.name ||
                              "Security finding"}
                          </td>

                          <td className="ops-mono">
                            {getResource(
                              finding
                            )}
                          </td>

                          <td>
                            {getService(
                              finding
                            )}
                          </td>

                          <td>
                            {formatAge(
                              finding?.detected_at ||
                                finding?.created_at ||
                                latestScanTimestamp
                            )}
                          </td>
                        </tr>
                      );
                    })}
                </tbody>

              </table>
            </div>
          ) : (
            <div className="ops-empty-inline">
              <CheckCircle2 size={17} />

              {hasScanData
                ? "No findings were reported by the latest scan."
                : "Run a scan to see findings here."}
            </div>
          )}
        </article>

        {/* AI INSIGHTS */}
        <article className="ops-panel ops-insights-panel">

          <div className="ops-panel-heading">
            <div>
              <span className="ops-eyebrow">
                AI ANALYSIS
              </span>

              <h2>
                <Bot size={17} /> AI security insights
              </h2>
            </div>

            <span className="ops-ai-mark">
              AI
            </span>
          </div>

          {recommendations.length ? (
            <ul className="ops-recommendations">

              {recommendations.map(
                (item, index) => (
                  <li
                    key={
                      item.id ||
                      item.finding_id ||
                      `${
                        item.title ||
                        item.name ||
                        "insight"
                      }-${index}`
                    }
                  >
                    <span className="ops-insight-icon">
                      <Activity size={15} />
                    </span>

                    <div className="ops-insight-copy">

                      <strong>
                        {item.title ||
                          item.name ||
                          item.finding ||
                          "Security recommendation"}
                      </strong>

                      <p>
                        {item.recommendation ||
                          item.recommended_action ||
                          item.description ||
                          item.business_impact ||
                          "Review this recommendation in the findings workspace."}
                      </p>

                    </div>

                    <Link
                      to="/findings"
                      aria-label="Review security findings"
                    >
                      <ArrowRight size={15} />
                    </Link>

                  </li>
                )
              )}

            </ul>
          ) : (
            <div className="ops-empty-insights">
              <Bot size={19} />

              <p>
                {hasScanData
                  ? "No AI recommendations were returned by the latest scan."
                  : "AI recommendations will appear after your first scan."}
              </p>
            </div>
          )}
        </article>

      </section>

      {/* QUICK ACTIONS */}
      <section
        className="ops-panel ops-quick-panel"
        aria-label="Quick actions"
      >
        <div className="ops-panel-heading">

          <div>
            <span className="ops-eyebrow">
              WORKSPACE
            </span>

            <h2>
              Quick actions
            </h2>
          </div>

        </div>

        <QuickActions
          onRefresh={loadDashboard}
        />
      </section>

      <AIChatWidget />

    </div>
  );
}

function MetricCard({
  icon: Icon,
  title,
  value,
  suffix = "",
  note,
  color,
}) {
  return (
    <article
      className={`ops-metric-card is-${color}`}
    >
      <div className="ops-metric-heading">
        <span>{title}</span>

        <Icon
          size={17}
          aria-hidden="true"
        />
      </div>

      <div className="ops-metric-value">
        {value}
        <small>{suffix}</small>
      </div>

      <div className="ops-metric-note">
        {note}
      </div>
    </article>
  );
}

function EmptyChart({ message }) {
  return (
    <div className="ops-empty-chart">
      <Activity size={18} />
      <span>{message}</span>
    </div>
  );
}

export default Dashboard;