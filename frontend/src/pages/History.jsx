
import { useCallback, useEffect, useMemo, useState } from "react";
import api from "../services/api";
import "./History.css";

function History() {
  const [scans, setScans] = useState([]);
  const [loading, setLoading] = useState(true);
  const [selectedScan, setSelectedScan] = useState(null);
  const [detailsLoading, setDetailsLoading] = useState(false);
  const [search, setSearch] = useState("");
  const [filter, setFilter] = useState("All");
  const [error, setError] = useState("");

  // ============================================================
  // LOAD SCAN HISTORY
  // ============================================================

  const loadHistory = useCallback(async () => {
    try {
      setLoading(true);
      setError("");

      const response = await api.get("/cloud/history");

      const data = response.data;

      let history = [];

      if (Array.isArray(data)) {
        history = data;
      } else if (Array.isArray(data?.history)) {
        history = data.history;
      } else if (Array.isArray(data?.data)) {
        history = data.data;
      } else if (Array.isArray(data?.scans)) {
        history = data.scans;
      }

      // Newest first
      history.sort((a, b) => {
        const dateA = new Date(
          a?.scan_time ||
            a?.created_at ||
            a?.timestamp ||
            0
        ).getTime();

        const dateB = new Date(
          b?.scan_time ||
            b?.created_at ||
            b?.timestamp ||
            0
        ).getTime();

        return dateB - dateA;
      });

      setScans(history);
    } catch (err) {
      console.error("[HISTORY LOAD ERROR]", err);

      setError(
        err?.response?.data?.detail ||
          err?.message ||
          "Failed to load scan history."
      );

      setScans([]);
    } finally {
      setLoading(false);
    }
  }, []);

  // ============================================================
  // INITIAL LOAD
  // ============================================================

  useEffect(() => {
    loadHistory();
  }, [loadHistory]);

  // ============================================================
  // INSPECT SCAN
  // ============================================================

  const inspectScan = async (scan) => {
    if (!scan?._id) {
      console.error("Scan ID missing:", scan);
      alert("Scan ID is missing.");
      return;
    }

    try {
      setDetailsLoading(true);
      setError("");

      // Show existing row immediately
      setSelectedScan(scan);

      console.log(
        "[INSPECT] Loading scan:",
        scan._id
      );

      const response = await api.get(
        `/cloud/history/${scan._id}`
      );

      console.log(
        "[INSPECT] Response:",
        response.data
      );

      const details =
        response.data?.scan ||
        response.data?.data ||
        response.data;

      if (details) {
        setSelectedScan(details);
        setScans((prevScans) =>
          prevScans.map((s) => (s._id === scan._id ? { ...s, ...details } : s))
        );
      } else {
        setSelectedScan(scan);
      }
    } catch (err) {
      console.error(
        "[INSPECT ERROR]",
        err
      );

      // Keep the existing scan visible
      setSelectedScan(scan);

      alert(
        err?.response?.data?.detail ||
          err?.message ||
          "Failed to load scan details."
      );
    } finally {
      setDetailsLoading(false);
    }
  };

  // ============================================================
  // DELETE SCAN
  // ============================================================

  const deleteScan = async (id) => {
    if (!id) {
      alert("Scan ID is missing.");
      return;
    }

    const confirmed = window.confirm(
      "Delete this scan history entry?"
    );

    if (!confirmed) {
      return;
    }

    try {
      console.log(
        "[DELETE] Scan:",
        id
      );

      await api.delete(
        `/cloud/history/${id}`
      );

      // Remove immediately from UI
      setScans((current) =>
        current.filter(
          (scan) => scan._id !== id
        )
      );

      // Close modal if deleted item was open
      if (selectedScan?._id === id) {
        setSelectedScan(null);
      }

      console.log(
        "[DELETE] Scan deleted successfully"
      );
    } catch (err) {
      console.error(
        "[DELETE ERROR]",
        err
      );

      alert(
        err?.response?.data?.detail ||
          err?.message ||
          "Failed to delete scan."
      );
    }
  };

  // ============================================================
  // FILTER + SEARCH
  // ============================================================

  const filteredScans = useMemo(() => {
    const keyword = search
      .trim()
      .toLowerCase();

    return scans.filter((scan) => {
      const account = String(
        scan?.account ||
          scan?.account_id ||
          scan?.aws_account_id ||
          ""
      ).toLowerCase();

      const level = String(
        scan?.security_level ||
          ""
      );

      const risk = String(
        scan?.risk_score ??
          ""
      );

      const matchesSearch =
        !keyword ||
        account.includes(keyword) ||
        level.toLowerCase().includes(keyword) ||
        risk.includes(keyword);

      const matchesFilter =
        filter === "All" ||
        level.toLowerCase() ===
          filter.toLowerCase();

      return (
        matchesSearch &&
        matchesFilter
      );
    });
  }, [scans, search, filter]);

  // ============================================================
  // HELPERS
  // ============================================================

  const getScanId = (scan) =>
    scan?._id ||
    scan?.scan_id ||
    scan?.id;

  const getAccount = (scan) =>
    scan?.account ||
    scan?.account_id ||
    scan?.aws_account_id ||
    "—";

  const getRiskScore = (scan) => {
    const value =
      scan?.risk_score ??
      scan?.riskScore;

    if (
      value === null ||
      value === undefined ||
      value === ""
    ) {
      return "—";
    }

    const number = Number(value);

    return Number.isFinite(number)
      ? number.toFixed(2)
      : String(value);
  };

  const getSecurityLevel = (scan) => {
    if (scan?.security_level) {
      return scan.security_level;
    }

    const score = Number(
      scan?.risk_score
    );

    if (!Number.isFinite(score)) {
      return "Unknown";
    }

    if (score >= 80) {
      return "Critical";
    }

    if (score >= 60) {
      return "High Risk";
    }

    if (score >= 40) {
      return "Medium Risk";
    }

    return "Low Risk";
  };

  const getScanDate = (scan) => {
    const value =
      scan?.scan_time ||
      scan?.created_at ||
      scan?.timestamp;

    if (!value) {
      return "—";
    }

    const date = new Date(value);

    if (Number.isNaN(date.getTime())) {
      return String(value);
    }

    return date.toLocaleString();
  };

  const getFindings = (scan) => {
    if (Array.isArray(scan?.findings)) {
      return scan.findings;
    }

    if (
      Array.isArray(
        scan?.scan?.findings
      )
    ) {
      return scan.scan.findings;
    }

    if (
      Array.isArray(
        scan?.result?.findings
      )
    ) {
      return scan.result.findings;
    }

    return [];
  };

  const getFindingTitle = (finding) =>
    finding?.issue ||
    finding?.title ||
    finding?.finding ||
    finding?.description ||
    "Security issue detected";

  const getSeverity = (finding) =>
    String(
      finding?.severity ||
        "UNKNOWN"
    ).toUpperCase();

  const getSeverityClass = (severity) =>
    `severity-${String(
      severity
    ).toLowerCase()}`;

  const getS3CoverageInfo = (scan) => {
    if (!scan) return { status: "UNAVAILABLE", total_buckets: 0, evaluated: false };
    if (scan.s3_coverage && typeof scan.s3_coverage === "object") {
      return {
        status: scan.s3_coverage.status || "UNKNOWN",
        total_buckets: scan.s3_coverage.total_buckets ?? (Array.isArray(scan.s3_inventory) ? scan.s3_inventory.length : 0),
        evaluated: Boolean(scan.s3_coverage.evaluated),
        error: scan.s3_coverage.error || null,
        uninspected_buckets: Array.isArray(scan.s3_coverage.uninspected_buckets) ? scan.s3_coverage.uninspected_buckets : [],
        message: scan.s3_coverage.message || null,
      };
    }
    if (Array.isArray(scan.s3_inventory)) {
      return {
        status: scan.s3_inventory.length === 0 ? "ZERO_DISCOVERED" : "COMPLETE",
        total_buckets: scan.s3_inventory.length,
        evaluated: true,
        error: null,
        uninspected_buckets: [],
        message: null,
      };
    }
    return {
      status: "UNAVAILABLE",
      total_buckets: scan?.resources?.s3 || 0,
      evaluated: false,
      error: null,
      uninspected_buckets: [],
      message: "S3 inventory and coverage details were not recorded in this historical scan.",
    };
  };

  const getS3Inventory = (scan) => {
    if (Array.isArray(scan?.s3_inventory)) {
      return scan.s3_inventory;
    }
    return null;
  };

  const getPostureClass = (posture) => {
    const p = String(posture || "").toUpperCase();
    if (p === "SECURE") return "posture-secure";
    if (p === "CRITICAL") return "posture-critical";
    if (p === "RISK") return "posture-risk";
    if (p === "EVALUATED") return "posture-evaluated";
    return "posture-unknown";
  };

  // ============================================================
  // UI
  // ============================================================

  return (
    <div className="history-page">
      {/* HEADER */}
      <div className="history-header">
        <div>
          <div className="history-eyebrow">
            CLOUD SECURITY
          </div>

          <h1>Scan History</h1>

          <p>
            Complete historical log of
            automated and manual cloud
            scans.
          </p>
        </div>

        <button
          className="history-refresh-button"
          onClick={loadHistory}
          disabled={loading}
        >
          ↻{" "}
          {loading
            ? "Refreshing..."
            : "Refresh History"}
        </button>
      </div>

      {/* TOOLBAR */}
      <div className="history-toolbar">
        <input
          type="text"
          value={search}
          onChange={(event) =>
            setSearch(event.target.value)
          }
          placeholder="Search Account ID or Security Level..."
        />

        <select
          value={filter}
          onChange={(event) =>
            setFilter(event.target.value)
          }
        >
          <option value="All">
            All
          </option>
          <option value="Critical">
            Critical
          </option>
          <option value="High Risk">
            High Risk
          </option>
          <option value="Medium Risk">
            Medium Risk
          </option>
          <option value="Low Risk">
            Low Risk
          </option>
        </select>
      </div>

      {/* ERROR */}
      {error && (
        <div className="history-error">
          {error}
        </div>
      )}

      {/* TABLE */}
      <div className="history-card">
        <div className="history-table-wrapper">
          <table className="history-table">
            <thead>
              <tr>
                <th>Date & Time</th>
                <th>AWS Account</th>
                <th>Risk Score</th>
                <th>Security Level</th>
                <th>Actions</th>
              </tr>
            </thead>

            <tbody>
              {loading ? (
                <tr>
                  <td
                    colSpan="5"
                    className="history-empty"
                  >
                    Loading scan history...
                  </td>
                </tr>
              ) : filteredScans.length ===
                0 ? (
                <tr>
                  <td
                    colSpan="5"
                    className="history-empty"
                  >
                    No scan records found.
                  </td>
                </tr>
              ) : (
                filteredScans.map(
                  (scan) => {
                    const id =
                      getScanId(scan);

                    const level =
                      getSecurityLevel(
                        scan
                      );

                    return (
                      <tr
                        key={id}
                      >
                        <td>
                          {getScanDate(
                            scan
                          )}
                        </td>

                        <td>
                          <strong>
                            {getAccount(
                              scan
                            )}
                          </strong>
                        </td>

                        <td>
                          <strong className="risk-score">
                            {getRiskScore(
                              scan
                            )}
                          </strong>
                        </td>

                        <td>
                          <span
                            className={`security-level ${String(
                              level
                            )
                              .toLowerCase()
                              .replace(
                                /\s+/g,
                                "-"
                              )}`}
                          >
                            {level}
                          </span>
                        </td>

                        <td>
                          <div className="history-actions">
                            <button
                              className="inspect-button"
                              onClick={() =>
                                inspectScan(
                                  scan
                                )
                              }
                            >
                              ◉ Inspect
                            </button>

                            <button
                              className="delete-button"
                              onClick={() =>
                                deleteScan(
                                  id
                                )
                              }
                            >
                              🗑 Delete
                            </button>
                          </div>
                        </td>
                      </tr>
                    );
                  }
                )
              )}
            </tbody>
          </table>
        </div>
      </div>

      {/* ========================================================
          INSPECTION MODAL
      ======================================================== */}

      {selectedScan && (
        <div
          className="scan-detail-modal-overlay"
          onClick={() =>
            setSelectedScan(null)
          }
        >
          <div
            className="scan-detail-modal"
            onClick={(event) =>
              event.stopPropagation()
            }
          >
            {/* MODAL HEADER */}
            <div className="scan-detail-header">
              <h2>
                Scan Inspection Details
              </h2>

              <button
                className="modal-close-button"
                onClick={() =>
                  setSelectedScan(null)
                }
              >
                ×
              </button>
            </div>

            {/* SUMMARY */}
            <div className="scan-detail-summary">
              <div>
                <span>
                  Account ID
                </span>

                <strong>
                  {getAccount(
                    selectedScan
                  )}
                </strong>
              </div>

              <div>
                <span>
                  Risk Score
                </span>

                <strong>
                  {getRiskScore(
                    selectedScan
                  )}
                </strong>
              </div>

              <div>
                <span>
                  Security Level
                </span>

                <strong>
                  {getSecurityLevel(
                    selectedScan
                  )}
                </strong>
              </div>

              <div>
                <span>
                  Timestamp
                </span>

                <strong>
                  {getScanDate(
                    selectedScan
                  )}
                </strong>
              </div>
            </div>

            {detailsLoading && (
              <div className="details-loading">
                Loading complete scan
                details...
              </div>
            )}

            {/* S3 INVENTORY & COVERAGE */}
            {(() => {
              if (
                detailsLoading &&
                selectedScan?.s3_coverage === undefined &&
                selectedScan?.s3_inventory === undefined
              ) {
                return (
                  <div className="scan-s3-section">
                    <div className="scan-s3-header">
                      <h3>S3 INVENTORY & COVERAGE</h3>
                      <span className="s3-coverage-badge badge-loading">
                        Loading details...
                      </span>
                    </div>
                    <div className="details-loading">
                      Loading S3 inventory & coverage details...
                    </div>
                  </div>
                );
              }

              const s3Coverage = getS3CoverageInfo(selectedScan);
              const s3Inventory = getS3Inventory(selectedScan);

              return (
                <div className="scan-s3-section">
                  <div className="scan-s3-header">
                    <h3>S3 INVENTORY & COVERAGE</h3>
                    <span className={`s3-coverage-badge badge-${s3Coverage.status.toLowerCase()}`}>
                      {s3Coverage.status === "COMPLETE" && "✓ Complete Coverage"}
                      {s3Coverage.status === "PARTIAL" && "⚠ Partial Coverage"}
                      {s3Coverage.status === "ZERO_DISCOVERED" && "0 Buckets Discovered"}
                      {s3Coverage.status === "FAILED" && "✕ Discovery Failed"}
                      {s3Coverage.status === "UNAVAILABLE" && "Historical (Unavailable)"}
                      {!["COMPLETE", "PARTIAL", "ZERO_DISCOVERED", "FAILED", "UNAVAILABLE"].includes(s3Coverage.status) && s3Coverage.status}
                    </span>
                  </div>

                  {s3Coverage.status === "UNAVAILABLE" && (
                    <div className="s3-notice-box notice-unavailable">
                      <div className="notice-title">S3 Inventory Not Recorded</div>
                      <p className="notice-desc">
                        {s3Coverage.message || "S3 bucket inventory and regional security posture were not captured in this historical scan. Run a fresh scan to view detailed S3 inventory."}
                      </p>
                      {selectedScan?.resources?.s3 !== undefined && (
                        <span className="notice-subtext">Historical Count: {selectedScan.resources.s3} S3 bucket(s)</span>
                      )}
                    </div>
                  )}

                  {s3Coverage.status === "FAILED" && (
                    <div className="s3-notice-box notice-failed">
                      <div className="notice-title">✕ S3 Discovery Failed</div>
                      <p className="notice-desc">
                        {s3Coverage.error || "The scanner encountered an error attempting to list or inspect S3 buckets."}
                      </p>
                      <span className="notice-subtext">Existing findings for S3 and other services are preserved and not falsely resolved.</span>
                    </div>
                  )}

                  {s3Coverage.status === "ZERO_DISCOVERED" && (
                    <div className="s3-notice-box notice-zero">
                      <div className="notice-title">No S3 Buckets Discovered</div>
                      <p className="notice-desc">
                        0 S3 buckets were discovered in this AWS account. S3 service posture has been evaluated as clean.
                      </p>
                    </div>
                  )}

                  {s3Coverage.status === "PARTIAL" && s3Coverage.uninspected_buckets?.length > 0 && (
                    <div className="s3-notice-box notice-warning">
                      <div className="notice-title">⚠ Partial S3 Inspection</div>
                      <p className="notice-desc">
                        {s3Coverage.uninspected_buckets.length} bucket(s) could not be fully verified: {s3Coverage.uninspected_buckets.join(", ")}. These resources were excluded from automatic finding resolution.
                      </p>
                    </div>
                  )}

                  {Array.isArray(s3Inventory) && s3Inventory.length > 0 && (
                    <div className="s3-inventory-list">
                      {s3Inventory.map((bucket, index) => {
                        const postureClass = getPostureClass(bucket?.security_posture);
                        return (
                          <div
                            key={bucket?.bucket_name || bucket?.resource || index}
                            className="s3-bucket-card"
                          >
                            <div className="s3-bucket-header">
                              <div className="s3-bucket-title">
                                <span className="s3-bucket-icon">🪣</span>
                                <span className="s3-bucket-name">{bucket?.bucket_name || bucket?.resource}</span>
                                <span className="s3-bucket-region">{bucket?.region || "Unknown"}</span>
                              </div>
                              <div className="s3-bucket-badges">
                                <span className={`s3-posture-badge ${postureClass}`}>
                                  {bucket?.security_posture || "UNKNOWN"}
                                </span>
                                <span className={`s3-cov-badge ${bucket?.coverage === "COMPLETE" ? "cov-complete" : "cov-partial"}`}>
                                  {bucket?.coverage || "PARTIAL"}
                                </span>
                              </div>
                            </div>

                            {bucket?.inspection_error && (
                              <div className="bucket-error-pill">
                                <strong>Inspection Error ({bucket.inspection_error.stage || "S3"}):</strong>{" "}
                                {bucket.inspection_error.message || bucket.inspection_error.error_code}
                              </div>
                            )}

                            <div className="s3-checks-grid">
                              <div className="s3-check-item">
                                <span className="check-label">Block Public Access</span>
                                <span className={`check-value ${bucket?.block_public_access?.all_protected ? "check-pass" : "check-warn"}`}>
                                  {bucket?.block_public_access?.all_protected ? "Protected" : (bucket?.block_public_access?.status || "Risk")}
                                </span>
                              </div>
                              <div className="s3-check-item">
                                <span className="check-label">Bucket Policy</span>
                                <span className={`check-value ${bucket?.bucket_policy?.is_public ? "check-fail" : "check-pass"}`}>
                                  {bucket?.bucket_policy?.is_public ? "Public" : (bucket?.bucket_policy?.status === "NO_POLICY" ? "None" : (bucket?.bucket_policy?.status || "Restricted"))}
                                </span>
                              </div>
                              <div className="s3-check-item">
                                <span className="check-label">Bucket ACL</span>
                                <span className={`check-value ${bucket?.acl?.public ? "check-fail" : "check-pass"}`}>
                                  {bucket?.acl?.public ? "Public ACL" : (bucket?.acl?.status || "Private")}
                                </span>
                              </div>
                              <div className="s3-check-item">
                                <span className="check-label">Server Encryption</span>
                                <span className={`check-value ${bucket?.encryption?.enabled ? "check-pass" : "check-warn"}`}>
                                  {bucket?.encryption?.enabled ? (bucket.encryption?.algorithm || "Enabled") : (bucket?.encryption?.status || "Disabled")}
                                </span>
                              </div>
                            </div>
                          </div>
                        );
                      })}
                    </div>
                  )}
                </div>
              );
            })()}

            {/* FINDINGS */}
            <div className="scan-findings-section">
              <h3>
                FINDINGS (
                {
                  getFindings(
                    selectedScan
                  ).length
                }
                )
              </h3>

              {getFindings(
                selectedScan
              ).length === 0 ? (
                <div className="no-findings">
                  No findings were returned
                  for this scan.
                </div>
              ) : (
                <div className="finding-list">
                  {getFindings(
                    selectedScan
                  ).map(
                    (
                      finding,
                      index
                    ) => {
                      const severity =
                        getSeverity(
                          finding
                        );

                      return (
                        <div
                          className="finding-item"
                          key={
                            finding?._id ||
                            finding?.id ||
                            index
                          }
                        >
                          <span
                            className={`finding-severity ${getSeverityClass(
                              severity
                            )}`}
                          >
                            {severity}
                          </span>

                          <span className="finding-title">
                            {getFindingTitle(
                              finding
                            )}
                          </span>
                        </div>
                      );
                    }
                  )}
                </div>
              )}
            </div>

            {/* EXTRA DETAILS */}
            {selectedScan.generated_policies &&
              Array.isArray(
                selectedScan.generated_policies
              ) &&
              selectedScan
                .generated_policies
                .length > 0 && (
                <div className="generated-policies">
                  <h3>
                    GENERATED POLICIES
                  </h3>

                  {selectedScan.generated_policies.map(
                    (
                      policy,
                      index
                    ) => (
                      <div
                        key={index}
                        className="policy-item"
                      >
                        {typeof policy ===
                        "string"
                          ? policy
                          : JSON.stringify(
                              policy
                            )}
                      </div>
                    )
                  )}
                </div>
              )}

            {/* FOOTER */}
            <div className="scan-detail-footer">
              <button
                className="close-details-button"
                onClick={() =>
                  setSelectedScan(null)
                }
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

export default History;

