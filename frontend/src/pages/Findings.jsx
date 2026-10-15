import { useEffect, useMemo, useState } from "react";
import { useSearchParams } from "react-router-dom";
import {
  AlertTriangle,
  Check,
  CircleHelp,
  Search,
  ShieldAlert,
  Sparkles,
  X,
} from "lucide-react";
import api from "../services/api";
import FindingRemediation from "../components/FindingRemediation";
import "./Findings.css";

function Findings() {
  const [searchParams] = useSearchParams();
  const [findings, setFindings] = useState([]);
  const [loading, setLoading] = useState(true);
  const [loadError, setLoadError] = useState(false);
  const [selectedFinding, setSelectedFinding] = useState(null);
  const [accountId, setAccountId] = useState(null);

  const [search, setSearch] = useState(() => searchParams.get("search") || "");
  const [severity, setSeverity] = useState("ALL");
  const [service, setService] = useState("ALL");
  const [resource, setResource] = useState("ALL");
  const [status, setStatus] = useState("ALL");
  const [sortBy, setSortBy] = useState("severity");

  // ============================================================
  // LOAD FINDINGS FROM LATEST SCAN
  // ============================================================

  useEffect(() => {
    loadFindings();
  }, []);

  const loadFindings = async () => {
    try {
      setLoading(true);
      setLoadError(false);

      const response = await api.get("/cloud/history");

      const data = response.data;

      let scans = [];

      if (Array.isArray(data)) {
        scans = data;
      } else if (Array.isArray(data?.scans)) {
        scans = data.scans;
      } else if (Array.isArray(data?.history)) {
        scans = data.history;
      } else if (Array.isArray(data?.data)) {
        scans = data.data;
      }

      if (scans.length === 0) {
        setFindings([]);
        setAccountId(null);
        return;
      }

      // Latest scan
      const latestScan = scans[0];
      setAccountId(latestScan?.account_id || latestScan?.scan?.account_id || null);

      let scanFindings =
        latestScan?.findings ||
        latestScan?.scan?.findings ||
        latestScan?.result?.findings ||
        [];

      // If findings are not included in lightweight history projection, load full scan details
      if ((!Array.isArray(scanFindings) || scanFindings.length === 0) && (latestScan?._id || latestScan?.id)) {
        try {
          const scanId = latestScan._id || latestScan.id;
          const detailRes = await api.get(`/cloud/history/${scanId}`);
          const detailedScan = detailRes.data?.scan || detailRes.data?.data || detailRes.data;
          scanFindings =
            detailedScan?.findings ||
            detailedScan?.scan?.findings ||
            detailedScan?.result?.findings ||
            [];
          if (!latestScan?.account_id && (detailedScan?.account_id || detailedScan?.scan?.account_id)) {
            setAccountId(detailedScan.account_id || detailedScan.scan?.account_id);
          }
        } catch (detailErr) {
          console.warn("Could not load detailed scan findings:", detailErr);
        }
      }

      if (Array.isArray(scanFindings)) {
        setFindings(
          scanFindings.map((finding, index) => ({
            ...finding,
            id:
              finding.finding_id ||
              finding._id ||
              `${index}-${finding.resource || "finding"}`,
            finding_id:
              finding.finding_id ||
              finding._id ||
              `F-${index + 1}`,
            scan_id:
              latestScan?._id ||
              latestScan?.scan_id ||
              latestScan?.id ||
              null,
          }))
        );
      } else {
        setFindings([]);
      }
    } catch (error) {
      console.error("Findings loading error:", error);
      setLoadError(true);
      setFindings([]);
      setAccountId(null);
    } finally {
      setLoading(false);
    }
  };

  // ============================================================
  // SERVICE NAME
  // ============================================================

  const getService = (finding) => {
    if (finding.service) {
      return String(finding.service).toUpperCase();
    }

    if (finding.resource_type) {
      return String(finding.resource_type).toUpperCase();
    }

    if (finding.bucket) {
      return "S3";
    }

    if (finding.security_group) {
      return "EC2";
    }

    if (finding.user) {
      return "IAM";
    }

    return "AWS";
  };

  // ============================================================
  // STATUS
  // ============================================================

  const getStatus = (finding) => {
    const value = String(
      finding.status || "OPEN"
    ).toUpperCase();

    if (
      value === "FAILED" ||
      value === "FAIL" ||
      value === "RISK"
    ) {
      return "OPEN";
    }

    if (
      value === "PROTECTED" ||
      value === "PASS" ||
      value === "PASSED"
    ) {
      return "PROTECTED";
    }

    if (
      value === "REVIEW" ||
      value === "WARNING"
    ) {
      return "REVIEW";
    }

    if (value === "UNKNOWN") {
      return "UNKNOWN";
    }

    return value;
  };

  // ============================================================
  // SEVERITY
  // ============================================================

  const severityOrder = {
    CRITICAL: 1,
    HIGH: 2,
    MEDIUM: 3,
    LOW: 4,
  };

  // ============================================================
  // SERVICES
  // ============================================================

  const services = useMemo(() => {
    const values = findings.map(getService);

    return [...new Set(values)].sort();
  }, [findings]);

  const resources = useMemo(() => {
    return [...new Set(findings.map((finding) => (
      finding.resource ||
      finding.bucket ||
      finding.security_group ||
      finding.user ||
      "AWS Resource"
    )))]
      .filter(Boolean)
      .sort();
  }, [findings]);

  // ============================================================
  // FILTER + SEARCH + SORT
  // ============================================================

  const filteredFindings = useMemo(() => {
    let result = [...findings];

    // Severity
    if (severity !== "ALL") {
      result = result.filter(
        (finding) =>
          String(finding.severity || "LOW").toUpperCase() ===
          severity
      );
    }

    // Service
    if (service !== "ALL") {
      result = result.filter(
        (finding) => getService(finding) === service
      );
    }

    if (resource !== "ALL") {
      result = result.filter((finding) => (
        finding.resource ||
        finding.bucket ||
        finding.security_group ||
        finding.user ||
        "AWS Resource"
      ) === resource);
    }

    // Status
    if (status !== "ALL") {
      result = result.filter(
        (finding) => getStatus(finding) === status
      );
    }

    // Search
    if (search.trim()) {
      const query = search.toLowerCase();

      result = result.filter((finding) => {
        const searchable = [
          finding.issue,
          finding.resource,
          finding.resource_type,
          finding.recommendation,
          finding.bucket,
          finding.security_group,
          finding.user,
          getService(finding),
        ]
          .filter(Boolean)
          .join(" ")
          .toLowerCase();

        return searchable.includes(query);
      });
    }

    // Sort
    if (sortBy === "severity") {
      result.sort(
        (a, b) =>
          (severityOrder[
            String(a.severity || "LOW").toUpperCase()
          ] || 5) -
          (severityOrder[
            String(b.severity || "LOW").toUpperCase()
          ] || 5)
      );
    }

    if (sortBy === "service") {
      result.sort((a, b) =>
        getService(a).localeCompare(getService(b))
      );
    }

    if (sortBy === "resource") {
      result.sort((a, b) =>
        String(a.resource || "").localeCompare(
          String(b.resource || "")
        )
      );
    }

    return result;
  }, [
    findings,
    severity,
    service,
    resource,
    status,
    search,
    sortBy,
  ]);

  // ============================================================
  // STATISTICS
  // ============================================================

  const stats = useMemo(() => {
    return {
      total: findings.length,

      critical: findings.filter(
        (f) =>
          String(f.severity || "").toUpperCase() ===
          "CRITICAL"
      ).length,

      high: findings.filter(
        (f) =>
          String(f.severity || "").toUpperCase() ===
          "HIGH"
      ).length,

      medium: findings.filter(
        (f) =>
          String(f.severity || "").toUpperCase() ===
          "MEDIUM"
      ).length,

      low: findings.filter(
        (f) =>
          String(f.severity || "").toUpperCase() ===
          "LOW"
      ).length,
    };
  }, [findings]);

  // ============================================================
  // SEVERITY CLASS
  // ============================================================

  const severityClass = (value) => {
    return String(value || "LOW")
      .toLowerCase()
      .replace(/\s+/g, "-");
  };

  // ============================================================
  // RENDER
  // ============================================================

  return (
    <div className="findings-page">

      {/* ======================================================
          PAGE HEADER
      ====================================================== */}

      <div className="findings-header">

        <div>
          <div className="page-kicker">
            SECURITY OPERATIONS
          </div>

          <h1>Findings</h1>

          <p>
            Identify, investigate and prioritize cloud
            security risks across your environment.
          </p>
        </div>

        <button
          className="refresh-findings"
          onClick={loadFindings}
          disabled={loading}
        >
          ↻ {loading ? "Refreshing..." : "Refresh"}
        </button>

      </div>

      {/* ======================================================
          STAT CARDS
      ====================================================== */}

      <div className="finding-stats">

        <div className="finding-stat total">
          <span className="stat-icon"><ShieldAlert size={17} /></span>

          <div>
            <span className="stat-label">
              Total Findings
            </span>

            <strong>{stats.total}</strong>
          </div>
        </div>

        <div className="finding-stat critical">
          <span className="stat-icon"><AlertTriangle size={17} /></span>

          <div>
            <span className="stat-label">
              Critical
            </span>

            <strong>{stats.critical}</strong>
          </div>
        </div>

        <div className="finding-stat high">
          <span className="stat-icon"><AlertTriangle size={17} /></span>

          <div>
            <span className="stat-label">
              High
            </span>

            <strong>{stats.high}</strong>
          </div>
        </div>

        <div className="finding-stat medium">
          <span className="stat-icon"><AlertTriangle size={17} /></span>

          <div>
            <span className="stat-label">
              Medium
            </span>

            <strong>{stats.medium}</strong>
          </div>
        </div>

        <div className="finding-stat low">
          <span className="stat-icon"><CircleHelp size={17} /></span>

          <div>
            <span className="stat-label">
              Low
            </span>

            <strong>{stats.low}</strong>
          </div>
        </div>

      </div>

      {/* ======================================================
          FILTER BAR
      ====================================================== */}

      <div className="findings-toolbar">

        <div className="finding-search">

          <Search size={16} aria-hidden="true" />

          <input
            type="text"
            placeholder="Search findings, resources, services..."
            value={search}
            onChange={(e) => setSearch(e.target.value)}
          />

          {search && (
            <button
              type="button"
              onClick={() => setSearch("")}
            >
              <X size={15} aria-hidden="true" />
            </button>
          )}

        </div>

        <select
          value={severity}
          onChange={(e) => setSeverity(e.target.value)}
        >
          <option value="ALL">
            All Severities
          </option>
          <option value="CRITICAL">
            Critical
          </option>
          <option value="HIGH">
            High
          </option>
          <option value="MEDIUM">
            Medium
          </option>
          <option value="LOW">
            Low
          </option>
        </select>

        <select
          value={service}
          onChange={(e) => setService(e.target.value)}
        >
          <option value="ALL">
            All Services
          </option>

          {services.map((item) => (
            <option key={item} value={item}>
              {item}
            </option>
          ))}
        </select>

        <select
          value={resource}
          onChange={(e) => setResource(e.target.value)}
        >
          <option value="ALL">All Resources</option>
          {resources.map((item) => (
            <option key={item} value={item}>{item}</option>
          ))}
        </select>

        <select
          value={status}
          onChange={(e) => setStatus(e.target.value)}
        >
          <option value="ALL">
            All Status
          </option>
          <option value="OPEN">
            Open
          </option>
          <option value="REVIEW">
            Review
          </option>
          <option value="PROTECTED">
            Protected
          </option>
          <option value="UNKNOWN">
            Unknown
          </option>
        </select>

        <select
          value={sortBy}
          onChange={(e) => setSortBy(e.target.value)}
        >
          <option value="severity">
            Sort: Risk
          </option>
          <option value="service">
            Sort: Service
          </option>
          <option value="resource">
            Sort: Resource
          </option>
        </select>

      </div>

      {/* ======================================================
          RESULT INFORMATION
      ====================================================== */}

      <div className="findings-result-bar">

        <span>
          Showing{" "}
          <strong>{filteredFindings.length}</strong>{" "}
          of{" "}
          <strong>{findings.length}</strong> findings
        </span>

        <span className="latest-scan-label">
          Latest security scan
        </span>

      </div>

      {/* ======================================================
          FINDINGS TABLE
      ====================================================== */}

      <div className="findings-table-card">

        {loading ? (

          <div className="findings-empty">
            <div className="loading-spinner"></div>

            <h3>Loading findings...</h3>

            <p>
              Fetching the latest cloud security results.
            </p>
          </div>

        ) : loadError ? (

          <div className="findings-empty">
            <div className="empty-icon error-state-mark">!</div>
            <h3>Findings could not be loaded</h3>
            <p>Try refreshing the workspace to retrieve the latest security results.</p>
            <button type="button" className="refresh-findings" onClick={loadFindings}>Try again</button>
          </div>

        ) : filteredFindings.length === 0 ? (

          <div className="findings-empty">

            <div className="empty-icon">
              ✓
            </div>

            <h3>
              No findings found
            </h3>

            <p>
              No findings match your current filters.
            </p>

          </div>

        ) : (

          <div className="findings-table-wrapper">

            <table className="findings-table">

              <thead>
                <tr>
                  <th>Severity</th>
                  <th>Finding</th>
                  <th>Service</th>
                  <th>Resource</th>
                  <th>Status</th>
                  <th>Detected</th>
                  <th></th>
                </tr>
              </thead>

              <tbody>

                {filteredFindings.map((finding) => (

                  <tr
                    key={finding.id}
                    onClick={() =>
                      setSelectedFinding(finding)
                    }
                  >

                    <td>
                      <span
                        className={`severity-badge ${severityClass(
                          finding.severity
                        )}`}
                      >
                        {String(finding.severity || "LOW").toUpperCase()}
                      </span>
                    </td>

                    <td>
                      <div className="finding-name-cell">

                        <div
                          className={`finding-severity-dot ${severityClass(
                            finding.severity
                          )}`}
                        ></div>

                        <div>

                          <strong>
                            {finding.issue ||
                              "Security Finding"}
                          </strong>

                          <span>
                            {finding.finding_id}
                          </span>

                        </div>

                      </div>
                    </td>

                    <td>
                      <span className="service-badge">
                        {getService(finding)}
                      </span>
                    </td>

                    <td>
                      <span className="resource-name">
                        {finding.resource ||
                          finding.bucket ||
                          finding.security_group ||
                          finding.user ||
                          "AWS Resource"}
                      </span>
                    </td>

                    <td>
                      <span
                        className={`status-badge-finding ${String(
                          getStatus(finding)
                        ).toLowerCase()}`}
                      >
                        {getStatus(finding)}
                      </span>
                    </td>

                    <td>
                      <span className="detected-value">
                        {finding.detected_at || finding.detected || finding.created_at || finding.scan_time || "—"}
                      </span>
                    </td>

                    <td>
                      <button
                        type="button"
                        className="view-finding"
                        onClick={(event) => {
                          event.stopPropagation();
                          setSelectedFinding(finding);
                        }}
                      >
                        View →
                      </button>
                    </td>

                  </tr>

                ))}

              </tbody>

            </table>

          </div>

        )}

      </div>

      {/* ======================================================
          FINDING DETAILS PANEL
      ====================================================== */}

      {selectedFinding && (

        <div
          className="finding-overlay"
          onClick={() => setSelectedFinding(null)}
        >

          <div
            className="finding-details"
            onClick={(event) => event.stopPropagation()}
          >

            <div className="details-header">

              <div>

                <span className="details-kicker">
                  SECURITY FINDING
                </span>

                <h2>
                  {selectedFinding.issue ||
                    "Security Finding"}
                </h2>

                <span className="finding-id">
                  {selectedFinding.finding_id}
                </span>

              </div>

              <button
                type="button"
                className="details-close"
                onClick={() =>
                  setSelectedFinding(null)
                }
              >
                <X size={18} aria-label="Close finding details" />
              </button>

            </div>

            {/* Severity + Status */}

            <div className="details-status-row">

              <span
                className={`severity-badge large ${severityClass(
                  selectedFinding.severity
                )}`}
              >
                {String(
                  selectedFinding.severity || "LOW"
                ).toUpperCase()}
              </span>

              <span
                className={`status-badge-finding large ${String(
                  getStatus(selectedFinding)
                ).toLowerCase()}`}
              >
                {getStatus(selectedFinding)}
              </span>

              <span className="service-badge large">
                {getService(selectedFinding)}
              </span>

            </div>

            <div className="details-layout">
              <div className="details-primary">

            {/* Affected Resource */}

            <section className="details-section">

              <h3>
                Affected Resource
              </h3>

              <div className="resource-box">

                <span>
                  Resource
                </span>

                <strong>
                  {selectedFinding.resource ||
                    selectedFinding.bucket ||
                    selectedFinding.security_group ||
                    selectedFinding.user ||
                    "AWS Resource"}
                </strong>

              </div>

              {selectedFinding.resource_type && (
                <div className="resource-meta">

                  <span>
                    Type
                  </span>

                  <strong>
                    {selectedFinding.resource_type}
                  </strong>

                </div>
              )}

            </section>

            {/* What is wrong */}

            <section className="details-section">

              <h3>
                What is wrong?
              </h3>

              <p>
                {selectedFinding.description || selectedFinding.issue || "No description was included in this finding."}
              </p>

            </section>

            {/* Evidence */}

            <section className="details-section">

              <h3>
                Security Evidence
              </h3>

              <div className="evidence-box">

                {Object.entries(selectedFinding)
                  .filter(
                    ([key]) =>
                      ![
                        "id",
                        "finding_id",
                        "scan_id",
                        "issue",
                        "recommendation",
                        "severity",
                        "status",
                      ].includes(key)
                  )
                  .slice(0, 12)
                  .map(([key, value]) => (

                    <div
                      className="evidence-row"
                      key={key}
                    >

                      <span>
                        {key.replaceAll("_", " ")}
                      </span>

                      <strong>
                        {typeof value === "object"
                          ? JSON.stringify(value)
                          : String(value)}
                      </strong>

                    </div>

                  ))}

              </div>

            </section>

              </div>
              <aside className="details-secondary">

            {selectedFinding.impact && (
              <section className="details-section">
                <h3>Why it matters</h3>
                <p>{selectedFinding.impact}</p>
              </section>
            )}

            {/* Remediation */}

            <FindingRemediation finding={selectedFinding} accountId={accountId} />

            {(selectedFinding.ai_analysis || selectedFinding.gemini_analysis) && (
            <section className="details-section ai-section">

              <div className="ai-title">
                <Sparkles size={16} />

                <h3>
                  AI Security Analysis
                </h3>
              </div>

              <p>
                {selectedFinding.ai_analysis || selectedFinding.gemini_analysis}
              </p>

            </section>
            )}

              </aside>
            </div>

          </div>

        </div>

      )}

    </div>
  );
}

export default Findings;