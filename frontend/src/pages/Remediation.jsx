import { useEffect, useMemo, useRef, useState } from "react";
import api from "../services/api";
import "./Remediation.css";

const STATUS_META = {
  PROPOSED: { label: "Proposed", className: "proposed" },
  PENDING_APPROVAL: { label: "Pending Approval", className: "pending" },
  APPROVED: { label: "Approved", className: "approved" },
  EXECUTING: { label: "Executing", className: "executing" },
  COMPLETED: { label: "Completed", className: "completed" },
  FAILED: { label: "Failed", className: "failed" },
  REJECTED: { label: "Rejected", className: "rejected" },
  CANCELLED: { label: "Cancelled", className: "cancelled" },
};

const SEVERITY_META = {
  CRITICAL: "critical",
  HIGH: "high",
  MEDIUM: "medium",
  LOW: "low",
};

const TERMINAL_STATUSES = new Set([
  "COMPLETED",
  "REJECTED",
  "CANCELLED",
]);

function normalizeStatus(value) {
  return String(value || "UNKNOWN").trim().toUpperCase();
}

function normalizeSeverity(value) {
  return String(value || "LOW").trim().toUpperCase();
}

function formatDate(value) {
  if (!value) return "—";

  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return "—";

  return date.toLocaleString();
}

function formatDuration(seconds) {
  if (seconds === null || seconds === undefined || seconds === "") {
    return "—";
  }

  const value = Number(seconds);
  if (!Number.isFinite(value)) return "—";
  if (value < 60) return `${value.toFixed(1)}s`;

  const minutes = Math.floor(value / 60);
  const remaining = Math.round(value % 60);
  return `${minutes}m ${remaining}s`;
}

function getRemediationId(item) {
  return item?._id || item?.id || item?.remediation_id;
}

function getFindingId(item) {
  return item?.finding_id || item?.source_finding_id || "—";
}

function getResource(item) {
  return item?.resource || item?.resource_id || "Unknown resource";
}

function getService(item) {
  return item?.service || "AWS";
}

function getAction(item) {
  return item?.action_type || item?.action || "—";
}

function formatActionLabel(value) {
  const raw = String(value || "").trim();
  if (!raw) return "—";

  return raw
    .toLowerCase()
    .split("_")
    .map((part) => part.charAt(0).toUpperCase() + part.slice(1))
    .join(" ");
}

function getStatusMeta(status) {
  const normalized = normalizeStatus(status);
  return (
    STATUS_META[normalized] || {
      label: normalized,
      className: "unknown",
    }
  );
}

function getErrorMessage(error) {
  return (
    error?.response?.data?.detail ||
    error?.response?.data?.message ||
    error?.response?.data?.error ||
    error?.message ||
    "Something went wrong."
  );
}

function getVerification(item) {
  return (
    item?.execution_result?.verification ||
    item?.after_state?.verification ||
    item?.execution_result?.after_state?.verification ||
    null
  );
}

function isVerified(item) {
  const result = item?.execution_result;
  const verification = getVerification(item);

  return Boolean(
    result?.success === true &&
      (verification?.verified === true || result?.verified === true)
  );
}

function getFindingTitle(item) {
  return (
    item?.title ||
    item?.finding_title ||
    item?.issue ||
    "Security remediation"
  );
}

function Remediation() {
  const [remediations, setRemediations] = useState([]);
  const [statistics, setStatistics] = useState({});
  const [selected, setSelected] = useState(null);

  const [loading, setLoading] = useState(true);
  const [actionLoading, setActionLoading] = useState(false);
  const [refreshing, setRefreshing] = useState(false);

  const [search, setSearch] = useState("");
  const [statusFilter, setStatusFilter] = useState("ALL");
  const [severityFilter, setSeverityFilter] = useState("ALL");
  const [sourceFilter, setSourceFilter] = useState("ALL");

  const [error, setError] = useState("");
  const [success, setSuccess] = useState("");
  const successTimerRef = useRef(null);

  useEffect(() => {
    loadRemediations(true);

    return () => {
      if (successTimerRef.current) {
        window.clearTimeout(successTimerRef.current);
      }
    };
  }, []);

  async function loadRemediations(initial = false) {
    if (initial) {
      setLoading(true);
    } else {
      setRefreshing(true);
    }

    setError("");

    try {
      const [listResponse, statisticsResponse] = await Promise.all([
        api.get("/remediation/"),
        api.get("/remediation/statistics"),
      ]);

      const list =
        listResponse?.data?.remediations ||
        listResponse?.data?.data ||
        [];

      const stats = statisticsResponse?.data?.statistics || {};
      const safeList = Array.isArray(list) ? list : [];

      setRemediations(safeList);
      setStatistics(stats);

      // Security Graph can deep-link here with a specific finding.
      // We only select an existing server-side remediation proposal;
      // navigation never creates or approves an AWS change.
      const params = new URLSearchParams(window.location.search);
      const requestedFindingId = params.get("finding_id");
      const requestedAccountId = params.get("account_id");

      setSelected((current) => {
        if (requestedFindingId) {
          const matching = safeList.find((item) => {
            const findingMatches =
              String(getFindingId(item)) === String(requestedFindingId);

            if (!findingMatches) {
              return false;
            }

            if (!requestedAccountId) {
              return true;
            }

            const itemAccountId = String(
              item?.account_id ||
                item?.aws_account_id ||
                ""
            );

            return (
              itemAccountId === String(requestedAccountId) ||
              item?.aws_account_id === String(requestedAccountId)
            );
          });

          if (matching) {
            return matching;
          }
        }

        if (!current) return null;

        const currentId = getRemediationId(current);
        return (
          safeList.find(
            (item) => getRemediationId(item) === currentId
          ) || current
        );
      });
    } catch (err) {
      console.error("Failed to load remediations:", err);
      setError(getErrorMessage(err));
    } finally {
      setLoading(false);
      setRefreshing(false);
    }
  }

  async function refreshSelected(id) {
    if (!id) return;

    try {
      const response = await api.get(`/remediation/${id}`);
      if (response?.data?.remediation) {
        setSelected(response.data.remediation);
      }
    } catch (err) {
      console.error("Failed to refresh remediation details:", err);
    }
  }

  const filteredRemediations = useMemo(() => {
    const query = search.trim().toLowerCase();

    return remediations.filter((item) => {
      const status = normalizeStatus(item?.status);
      const severity = normalizeSeverity(item?.severity);

      const searchableText = [
        getRemediationId(item),
        getFindingId(item),
        getService(item),
        getResource(item),
        getAction(item),
        getFindingTitle(item),
        item?.description,
        item?.reason,
        item?.recommendation,
        item?.aws_account_id,
      ]
        .filter(Boolean)
        .join(" ")
        .toLowerCase();

      const itemSource = String(item?.source || "rule").toLowerCase();
      const matchesSource =
        sourceFilter === "ALL" ||
        (sourceFilter === "AI" && itemSource === "ai") ||
        (sourceFilter === "RULE" && itemSource !== "ai");

      return (
        (!query || searchableText.includes(query)) &&
        (statusFilter === "ALL" || status === statusFilter) &&
        (severityFilter === "ALL" || severity === severityFilter) &&
        matchesSource
      );
    });
  }, [remediations, search, statusFilter, severityFilter, sourceFilter]);

  const counts = useMemo(() => {
    const result = {
      total: remediations.length,
      proposed: 0,
      pendingApproval: 0,
      approved: 0,
      executing: 0,
      completed: 0,
      failed: 0,
      rejected: 0,
      cancelled: 0,
    };

    remediations.forEach((item) => {
      const status = normalizeStatus(item?.status);

      if (status === "PROPOSED") {
        result.proposed += 1;
      } else if (status === "PENDING_APPROVAL") {
        result.pendingApproval += 1;
      } else if (status === "APPROVED") {
        result.approved += 1;
      } else if (status === "EXECUTING") {
        result.executing += 1;
      } else if (status === "COMPLETED") {
        result.completed += 1;
      } else if (status === "FAILED") {
        result.failed += 1;
      } else if (status === "REJECTED") {
        result.rejected += 1;
      } else if (status === "CANCELLED") {
        result.cancelled += 1;
      }
    });

    return result;
  }, [remediations]);

  const displayedCounts = {
    total: statistics?.total ?? counts.total,
    proposed:
      statistics?.proposed ??
      statistics?.pending_approval ??
      counts.proposed + counts.pendingApproval,
    approved: statistics?.approved ?? counts.approved,
    executing: statistics?.executing ?? counts.executing,
    completed: statistics?.completed ?? counts.completed,
    failed: statistics?.failed ?? counts.failed,
  };

  function showSuccess(message) {
    setSuccess(message);

    if (successTimerRef.current) {
      window.clearTimeout(successTimerRef.current);
    }

    successTimerRef.current = window.setTimeout(() => {
      setSuccess("");
    }, 5000);
  }

  function selectRemediation(item) {
    setSelected(item);
    setError("");
    setSuccess("");
  }

  async function approveRemediation() {
    if (!selected || actionLoading) return;

    const id = getRemediationId(selected);
    if (!id) {
      setError("Remediation ID is missing.");
      return;
    }

    const confirmed = window.confirm(
      "Approve this remediation proposal? Approval does not change AWS yet."
    );

    if (!confirmed) return;

    setActionLoading(true);
    setError("");
    setSuccess("");

    try {
      const response = await api.patch(`/remediation/${id}/approve`, {
        comment: "Approved from CloudGuardAI Remediation Center",
      });

      if (response?.data?.remediation) {
        setSelected(response.data.remediation);
      }

      showSuccess(
        "Remediation approved. AWS will not change until execution is started."
      );
      await loadRemediations();
    } catch (err) {
      console.error("Failed to approve remediation:", err);
      setError(getErrorMessage(err));
    } finally {
      setActionLoading(false);
    }
  }

  async function executeRemediation() {
    if (!selected || actionLoading) return;

    const id = getRemediationId(selected);
    if (!id) {
      setError("Remediation ID is missing.");
      return;
    }

    if (normalizeStatus(selected.status) !== "APPROVED") {
      setError("Only an approved remediation can be executed.");
      return;
    }

    const confirmed = window.confirm(
      "This action will make a real AWS security change. Continue?"
    );

    if (!confirmed) return;

    setActionLoading(true);
    setError("");
    setSuccess("");

    try {
      const response = await api.post(`/remediation/${id}/execute`, {
        confirmed: true,
      });
      const result = response?.data?.remediation;

      if (
        response?.data?.status === "failed" ||
        result?.success === false
      ) {
        setError(
          result?.error ||
            result?.message ||
            "AWS remediation failed. Review the execution result before retrying."
        );
      } else {
        showSuccess(
          "AWS remediation completed and the resulting state was verified."
        );
      }

      await loadRemediations();
      await refreshSelected(id);
    } catch (err) {
      console.error("Failed to execute remediation:", err);
      setError(getErrorMessage(err));
      await loadRemediations();
      await refreshSelected(id);
    } finally {
      setActionLoading(false);
    }
  }

  async function rejectRemediation() {
    if (!selected || actionLoading) return;

    const id = getRemediationId(selected);
    if (!id) {
      setError("Remediation ID is missing.");
      return;
    }

    const reason = window.prompt(
      "Enter the reason for rejecting this remediation:"
    );

    if (!reason || !reason.trim()) return;

    setActionLoading(true);
    setError("");
    setSuccess("");

    try {
      const response = await api.patch(`/remediation/${id}/reject`, {
        reason: reason.trim(),
      });

      if (response?.data?.remediation) {
        setSelected(response.data.remediation);
      }

      showSuccess("Remediation rejected.");
      await loadRemediations();
    } catch (err) {
      console.error("Failed to reject remediation:", err);
      setError(getErrorMessage(err));
    } finally {
      setActionLoading(false);
    }
  }

  async function cancelRemediation() {
    if (!selected || actionLoading) return;

    const id = getRemediationId(selected);
    if (!id) {
      setError("Remediation ID is missing.");
      return;
    }

    const confirmed = window.confirm(
      "Cancel this remediation proposal?"
    );

    if (!confirmed) return;

    setActionLoading(true);
    setError("");
    setSuccess("");

    try {
      const response = await api.patch(`/remediation/${id}/cancel`);

      if (response?.data?.remediation) {
        setSelected(response.data.remediation);
      }

      showSuccess("Remediation cancelled.");
      await loadRemediations();
    } catch (err) {
      console.error("Failed to cancel remediation:", err);
      setError(getErrorMessage(err));
    } finally {
      setActionLoading(false);
    }
  }

  async function deleteRemediation() {
    if (!selected || actionLoading) return;

    const id = getRemediationId(selected);
    if (!id) {
      setError("Remediation ID is missing.");
      return;
    }

    const confirmed = window.confirm(
      "Delete this remediation record? This does not undo any AWS change."
    );

    if (!confirmed) return;

    setActionLoading(true);
    setError("");
    setSuccess("");

    try {
      await api.delete(`/remediation/${id}`);
      setSelected(null);
      showSuccess("Remediation record deleted.");
      await loadRemediations();
    } catch (err) {
      console.error("Failed to delete remediation:", err);
      setError(getErrorMessage(err));
    } finally {
      setActionLoading(false);
    }
  }

  const requestedFindingId =
    new URLSearchParams(window.location.search).get("finding_id");

  const selectedStatus = normalizeStatus(selected?.status);
  const selectedStatusMeta = getStatusMeta(selectedStatus);
  const selectedVerification = selected ? getVerification(selected) : null;
  const selectedVerified = selected ? isVerified(selected) : false;

  return (
    <div className="remediation-page">
      <section className="remediation-header">
        <div>
          <div className="page-eyebrow">SECURITY OPERATIONS</div>
          <h1>Remediation Center</h1>
          <p>
            Review, approve and securely execute AWS security remediations.
          </p>
        </div>

        <button
          className="refresh-button"
          onClick={() => loadRemediations()}
          disabled={loading || refreshing || actionLoading}
          type="button"
        >
          {refreshing ? "↻ Refreshing..." : "↻ Refresh"}
        </button>
      </section>

      <div className="remediation-security-note">
        <span className="security-note-icon">✓</span>
        <div>
          <strong>Controlled AWS changes</strong>
          <span>
            CloudGuardAI requires approval before execution and verifies the
            resulting AWS state before marking a finding resolved.
          </span>
        </div>
      </div>

      {error && (
        <div className="remediation-alert error" role="alert">
          <strong>Action failed</strong>
          <span>{error}</span>
          <button onClick={() => setError("")} type="button" aria-label="Dismiss error">
            ×
          </button>
        </div>
      )}

      {success && (
        <div className="remediation-alert success" role="status">
          <strong>Success</strong>
          <span>{success}</span>
          <button onClick={() => setSuccess("")} type="button" aria-label="Dismiss success">
            ×
          </button>
        </div>
      )}

      <section className="remediation-summary">
        <SummaryCard label="Total" value={displayedCounts.total} icon="◈" className="blue" />
        <SummaryCard label="Awaiting Approval" value={displayedCounts.proposed} icon="◷" className="orange" />
        <SummaryCard label="Approved" value={displayedCounts.approved} icon="✓" className="purple" />
        <SummaryCard label="Executing" value={displayedCounts.executing} icon="⚡" className="cyan" />
        <SummaryCard label="Completed" value={displayedCounts.completed} icon="✓" className="green" />
        <SummaryCard label="Failed" value={displayedCounts.failed} icon="!" className="red" />
      </section>

      {requestedFindingId && (
        <div
          className="remediation-security-note"
          role="status"
          style={{ marginBottom: 12 }}
        >
          <strong>Finding context:</strong>{" "}
          {requestedFindingId}
          {selected
            ? " — matching remediation selected."
            : " — no matching remediation proposal exists yet."}
        </div>
      )}

      <section className="remediation-toolbar">
        <div className="remediation-search">
          <span aria-hidden="true">⌕</span>
          <input
            type="text"
            placeholder="Search finding, resource, service..."
            value={search}
            onChange={(event) => setSearch(event.target.value)}
            aria-label="Search remediations"
          />
        </div>

        <select
          value={statusFilter}
          onChange={(event) => setStatusFilter(event.target.value)}
          aria-label="Filter by status"
        >
          <option value="ALL">All statuses</option>
          <option value="PROPOSED">Proposed</option>
          <option value="PENDING_APPROVAL">Pending approval</option>
          <option value="APPROVED">Approved</option>
          <option value="EXECUTING">Executing</option>
          <option value="COMPLETED">Completed</option>
          <option value="FAILED">Failed</option>
          <option value="REJECTED">Rejected</option>
          <option value="CANCELLED">Cancelled</option>
        </select>

        <select
          value={severityFilter}
          onChange={(event) => setSeverityFilter(event.target.value)}
          aria-label="Filter by severity"
        >
          <option value="ALL">All severities</option>
          <option value="CRITICAL">Critical</option>
          <option value="HIGH">High</option>
          <option value="MEDIUM">Medium</option>
          <option value="LOW">Low</option>
        </select>

        <select
          value={sourceFilter}
          onChange={(event) => setSourceFilter(event.target.value)}
          aria-label="Filter by proposal source"
        >
          <option value="ALL">All sources</option>
          <option value="AI">✨ AI Proposed</option>
          <option value="RULE">Rule-based Engine</option>
        </select>
      </section>

      <section className="remediation-workspace">
        <div className="remediation-table-card">
          <div className="card-heading">
            <div>
              <h2>Remediation Queue</h2>
              <span>{filteredRemediations.length} records</span>
            </div>
          </div>

          {loading ? (
            <div className="remediation-empty">
              <div className="loading-spinner" />
              <p>Loading remediation records...</p>
            </div>
          ) : filteredRemediations.length === 0 ? (
            <div className="remediation-empty">
              <div className="empty-icon">✓</div>
              <h3>No remediations found</h3>
              <p>
                Remediation proposals will appear here when security findings
                are ready for action.
              </p>
            </div>
          ) : (
            <div className="remediation-table-wrapper">
              <table className="remediation-table">
                <thead>
                  <tr>
                    <th>Finding</th>
                    <th>Service</th>
                    <th>Resource</th>
                    <th>Severity</th>
                    <th>Action</th>
                    <th>Status</th>
                  </tr>
                </thead>
                <tbody>
                  {filteredRemediations.map((item) => {
                    const id = getRemediationId(item);
                    const severity = normalizeSeverity(item?.severity);
                    const status = normalizeStatus(item?.status);
                    const statusMeta = getStatusMeta(status);
                    const selectedId = getRemediationId(selected);

                    return (
                      <tr
                        key={id}
                        className={selectedId === id ? "selected-row" : ""}
                        onClick={() => selectRemediation(item)}
                        tabIndex={0}
                        onKeyDown={(event) => {
                          if (event.key === "Enter" || event.key === " ") {
                            event.preventDefault();
                            selectRemediation(item);
                          }
                        }}
                      >
                        <td>
                          <div className="finding-cell">
                            <div className="finding-id-row">
                              <strong>{getFindingId(item)}</strong>
                              {String(item?.source || "").toLowerCase() === "ai" && (
                                <span className="ai-source-badge" title="Proposed by Gemini AI Reasoning Engine">
                                  ✨ AI Proposed
                                </span>
                              )}
                            </div>
                            <span>{getFindingTitle(item)}</span>
                          </div>
                        </td>
                        <td>
                          <span className="service-badge">{getService(item)}</span>
                        </td>
                        <td>
                          <div className="resource-cell" title={getResource(item)}>
                            {getResource(item)}
                          </div>
                        </td>
                        <td>
                          <span
                            className={`severity-badge ${
                              SEVERITY_META[severity] || "low"
                            }`}
                          >
                            {severity}
                          </span>
                        </td>
                        <td>
                          <span className="action-text">{formatActionLabel(getAction(item))}</span>
                        </td>
                        <td>
                          <span className={`status-badge ${statusMeta.className}`}>
                            <span className="status-dot" />
                            {statusMeta.label}
                          </span>
                        </td>
                      </tr>
                    );
                  })}
                </tbody>
              </table>
            </div>
          )}
        </div>

        <aside className="remediation-details-card">
          {!selected ? (
            <div className="details-placeholder">
              <div className="details-placeholder-icon">◇</div>
              <h3>Select a remediation</h3>
              <p>
                Select a remediation from the queue to review its security
                impact, AWS resource and workflow actions.
              </p>
            </div>
          ) : (
            <>
              <div className="details-header">
                <div>
                  <span className="details-label">REMEDIATION</span>
                  <h2>{getFindingTitle(selected)}</h2>
                </div>
                <span className={`status-badge ${selectedStatusMeta.className}`}>
                  <span className="status-dot" />
                  {selectedStatusMeta.label}
                </span>
              </div>

              <div className="details-id">{getRemediationId(selected)}</div>

              {((selected.source && String(selected.source).toLowerCase() === "ai") || (selected.metadata && selected.metadata.confidence !== undefined)) && (
                <div className="detail-section ai-intelligence-section">
                  <div className="ai-section-header">
                    <div className="ai-title-group">
                      <span className="ai-sparkle-icon">✨</span>
                      <h3>AI Proposal Intelligence</h3>
                    </div>
                    <span className="ai-model-tag">
                      {selected.metadata?.model || "gemini-3.6-flash"}
                    </span>
                  </div>

                  {typeof selected.metadata?.confidence === "number" && (
                    <div className="ai-confidence-block">
                      <div className="ai-confidence-header">
                        <span>Confidence Score</span>
                        <span className="ai-confidence-meter-label">
                          <strong className="ai-confidence-value">
                            {Math.round(selected.metadata.confidence * 100)}%
                          </strong>
                          <span className="ai-confidence-pill high">PASSED GATE</span>
                        </span>
                      </div>
                      <div className="ai-confidence-meter" role="progressbar" aria-valuenow={Math.round(selected.metadata.confidence * 100)} aria-valuemin="0" aria-valuemax="100">
                        <div
                          className="ai-confidence-fill"
                          style={{ width: `${Math.min(100, Math.max(0, Math.round(selected.metadata.confidence * 100)))}%` }}
                        />
                      </div>
                      <span className="ai-confidence-subtext">
                        Deterministic safety gate passed with high certainty (&ge; 60% threshold)
                      </span>
                    </div>
                  )}

                  {(selected.metadata?.rationale || selected.reason) && (
                    <div className="ai-card-block rationale">
                      <span className="ai-card-label">AI Rationale</span>
                      <p className="ai-card-text">
                        {selected.metadata?.rationale || selected.reason}
                      </p>
                    </div>
                  )}

                  {selected.metadata?.risk_notes && (
                    <div className="ai-card-block risk">
                      <span className="ai-card-label">Risk Assessment & Blast Radius</span>
                      <p className="ai-card-text">{selected.metadata.risk_notes}</p>
                    </div>
                  )}
                </div>
              )}

              <div className="detail-section">
                <h3>Finding</h3>
                <div className="detail-grid">
                  <DetailItem label="Finding ID" value={getFindingId(selected)} />
                  <DetailItem label="Severity" value={normalizeSeverity(selected.severity)} />
                  <DetailItem label="Service" value={getService(selected)} />
                  <DetailItem label="Resource" value={getResource(selected)} />
                  <DetailItem label="Action" value={formatActionLabel(getAction(selected))} />
                  <DetailItem
                    label="AWS Account"
                    value={selected.aws_account_id || selected.account_id}
                  />
                </div>
              </div>

              <div className="detail-section">
                <h3>What will happen?</h3>
                <p className="detail-description">
                  {selected.description ||
                    "CloudGuardAI will execute the approved security remediation and verify the resulting AWS state."}
                </p>
              </div>

              {selected.reason && (
                <div className="detail-section">
                  <h3>Why this matters</h3>
                  <p className="detail-description">{selected.reason}</p>
                </div>
              )}

              {selected.recommendation && (
                <div className="detail-section">
                  <h3>Recommendation</h3>
                  <p className="detail-description">{selected.recommendation}</p>
                </div>
              )}

              <div className="detail-section">
                <h3>Workflow</h3>
                <Workflow status={selectedStatus} />
              </div>

              {selected.execution_result && (
                <div className="detail-section">
                  <h3>Execution Result</h3>
                  <div className="execution-result">
                    <div>
                      <span>Result</span>
                      <strong>
                        {selectedVerified
                          ? "Verified"
                          : selected.execution_result.success
                            ? "Completed"
                            : "Failed"}
                      </strong>
                    </div>

                    {selected.execution_result.message && (
                      <p>{selected.execution_result.message}</p>
                    )}

                    {selected.execution_result.error && (
                      <p className="execution-error">
                        {selected.execution_result.error}
                      </p>
                    )}

                    {selected.execution_result.duration_seconds !== undefined && (
                      <div className="execution-meta-row">
                        <span>Duration</span>
                        <strong>
                          {formatDuration(
                            selected.execution_result.duration_seconds
                          )}
                        </strong>
                      </div>
                    )}

                    {selectedVerified && (
                      <div className="verification-banner">
                        <span>✓</span>
                        <div>
                          <strong>AWS state verified</strong>
                          <small>
                            The post-remediation state matched the expected
                            security condition.
                          </small>
                        </div>
                      </div>
                    )}
                  </div>
                </div>
              )}

              {selectedVerification && (
                <div className="detail-section">
                  <h3>Verification Evidence</h3>
                  <div className="verification-grid">
                    {Object.entries(selectedVerification)
                      .filter(([key]) => key !== "verified")
                      .slice(0, 8)
                      .map(([key, value]) => (
                        <DetailItem
                          key={key}
                          label={key.replaceAll("_", " ")}
                          value={
                            typeof value === "boolean"
                              ? value
                                ? "Yes"
                                : "No"
                              : typeof value === "object"
                                ? JSON.stringify(value)
                                : String(value)
                          }
                        />
                      ))}
                  </div>
                </div>
              )}

              <div className="detail-section">
                <h3>Timeline</h3>
                <div className="timeline-info">
                  <div>
                    <span>Created</span>
                    <strong>{formatDate(selected.created_at)}</strong>
                  </div>
                  <div>
                    <span>Updated</span>
                    <strong>{formatDate(selected.updated_at)}</strong>
                  </div>
                  {selected.approved_at && (
                    <div>
                      <span>Approved</span>
                      <strong>{formatDate(selected.approved_at)}</strong>
                    </div>
                  )}
                  {selected.started_at && (
                    <div>
                      <span>Execution started</span>
                      <strong>{formatDate(selected.started_at)}</strong>
                    </div>
                  )}
                  {selected.completed_at && (
                    <div>
                      <span>Completed</span>
                      <strong>{formatDate(selected.completed_at)}</strong>
                    </div>
                  )}
                </div>
              </div>

              <div className="detail-actions">
                {(selectedStatus === "PROPOSED" ||
                  selectedStatus === "PENDING_APPROVAL") && (
                  <>
                    <button
                      className="action-button approve"
                      onClick={approveRemediation}
                      disabled={actionLoading}
                      type="button"
                    >
                      {actionLoading ? "Processing..." : "✓ Approve"}
                    </button>
                    <button
                      className="action-button reject"
                      onClick={rejectRemediation}
                      disabled={actionLoading}
                      type="button"
                    >
                      Reject
                    </button>
                    <button
                      className="action-button cancel"
                      onClick={cancelRemediation}
                      disabled={actionLoading}
                      type="button"
                    >
                      Cancel
                    </button>
                  </>
                )}

                {selectedStatus === "APPROVED" && (
                  <button
                    className="action-button execute"
                    onClick={executeRemediation}
                    disabled={actionLoading}
                    type="button"
                  >
                    {actionLoading ? "Executing..." : "⚡ Execute AWS Remediation"}
                  </button>
                )}

                {selectedStatus === "FAILED" && (
                  <div className="reapproval-required">
                    <strong>Re-approval required</strong>
                    <span>
                      A failed remediation cannot be executed directly. Create
                      or approve a new remediation proposal after reviewing the
                      failure.
                    </span>
                  </div>
                )}

                {TERMINAL_STATUSES.has(selectedStatus) &&
                  selectedStatus !== "COMPLETED" && (
                    <button
                      className="action-button delete"
                      onClick={deleteRemediation}
                      disabled={actionLoading}
                      type="button"
                    >
                      Delete Record
                    </button>
                  )}
              </div>
            </>
          )}
        </aside>
      </section>
    </div>
  );
}

function SummaryCard({ label, value, icon, className }) {
  return (
    <div className={`summary-card ${className}`}>
      <div className="summary-icon">{icon}</div>
      <div>
        <span>{label}</span>
        <strong>{value ?? 0}</strong>
      </div>
    </div>
  );
}

function DetailItem({ label, value }) {
  return (
    <div className="detail-item">
      <span>{label}</span>
      <strong title={String(value ?? "—")}>{value || "—"}</strong>
    </div>
  );
}

function Workflow({ status }) {
  const steps = [
    "PROPOSED",
    "PENDING_APPROVAL",
    "APPROVED",
    "EXECUTING",
    "COMPLETED",
  ];

  const normalizedStatus = normalizeStatus(status);
  const currentIndex = steps.indexOf(normalizedStatus);

  const failed = normalizedStatus === "FAILED";
  const rejected = normalizedStatus === "REJECTED";
  const cancelled = normalizedStatus === "CANCELLED";

  // A terminal failure occurs during the execution stage.
  const effectiveIndex = failed
    ? steps.indexOf("EXECUTING")
    : currentIndex;

  return (
    <div className="workflow" aria-label="Remediation workflow">
      {steps.map((step, index) => {
        const completed =
          !rejected &&
          !cancelled &&
          effectiveIndex >= index &&
          !(failed && step === "EXECUTING");

        const active =
          normalizedStatus === step ||
          (failed && step === "EXECUTING");

        return (
          <div className="workflow-step" key={step}>
            <div
              className={`workflow-node ${completed ? "completed" : ""} ${
                active ? "active" : ""
              } ${failed && step === "EXECUTING" ? "failed" : ""}`}
              aria-current={active ? "step" : undefined}
            >
              {completed ? "✓" : index + 1}
            </div>

            <span>
              {step === "PENDING_APPROVAL"
                ? "PENDING APPROVAL"
                : step.replace("_", " ")}
            </span>

            {index < steps.length - 1 && (
              <div
                className={`workflow-line ${
                  effectiveIndex > index && !failed ? "filled" : ""
                }`}
              />
            )}
          </div>
        );
      })}

      {(failed || rejected || cancelled) && (
        <div className="workflow-terminal">
          {failed &&
            "Execution failed — review the execution evidence and create a new proposal before another AWS change."}
          {rejected && "This remediation was rejected and cannot be executed."}
          {cancelled && "This remediation was cancelled and cannot be executed."}
        </div>
      )}

      {!failed && !rejected && !cancelled && normalizedStatus === "COMPLETED" && (
        <div className="workflow-terminal">
          AWS change completed and post-remediation state was verified.
        </div>
      )}
    </div>
  );
}

export default Remediation;
