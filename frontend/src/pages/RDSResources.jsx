import { useCallback, useEffect, useId, useMemo, useRef, useState } from "react";
import { Link } from "react-router-dom";
import {
  HardDrive,
  RefreshCw,
  Search,
  AlertTriangle,
  ChevronLeft,
  ChevronRight,
  Shield,
  ShieldCheck,
  CheckCircle2,
  AlertCircle,
  Activity,
  Play,
  Square,
  RotateCw,
  Lock,
  Unlock,
  Key,
  Server,
  Database,
  Layers,
  Network,
  Clock,
  X,
  Eye,
  Info,
  ExternalLink,
} from "lucide-react";
import {
  getAWSAccounts,
  getRDSInstances,
  getRDSClusters,
  controlRDSInstance,
} from "../services/awsService";
import "./RDSResources.css";

const STANDARD_AWS_REGIONS = [
  { id: "us-east-1", name: "US East (N. Virginia) - us-east-1" },
  { id: "us-east-2", name: "US East (Ohio) - us-east-2" },
  { id: "us-west-1", name: "US West (N. California) - us-west-1" },
  { id: "us-west-2", name: "US West (Oregon) - us-west-2" },
  { id: "ap-south-1", name: "Asia Pacific (Mumbai) - ap-south-1" },
  { id: "eu-west-1", name: "Europe (Ireland) - eu-west-1" },
  { id: "eu-central-1", name: "Europe (Frankfurt) - eu-central-1" },
  { id: "ap-southeast-1", name: "Asia Pacific (Singapore) - ap-southeast-1" },
  { id: "ap-northeast-1", name: "Asia Pacific (Tokyo) - ap-northeast-1" },
  { id: "sa-east-1", name: "South America (São Paulo) - sa-east-1" },
];

export default function RDSResources() {
  const accountSelectId = useId();
  const regionSelectId = useId();
  const searchInputId = useId();
  const engineFilterId = useId();
  const statusFilterId = useId();
  const postureFilterId = useId();
  const confirmCheckId = useId();

  // Accounts state
  const [accounts, setAccounts] = useState([]);
  const [accountsLoading, setAccountsLoading] = useState(true);
  const [selectedAccountId, setSelectedAccountId] = useState("");

  // Inventory state
  const [selectedRegion, setSelectedRegion] = useState("us-east-1");
  const [instances, setInstances] = useState([]);
  const [clusters, setClusters] = useState([]);
  const [summary, setSummary] = useState(null);
  const [totalCount, setTotalCount] = useState(0);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState(null);
  const [lastRefreshed, setLastRefreshed] = useState(null);

  // Pagination state
  const [nextToken, setNextToken] = useState(null);
  const [previousTokens, setPreviousTokens] = useState([]);
  const [currentToken, setCurrentToken] = useState(null);
  const [pageSize, setPageSize] = useState(50);

  // Search & filters
  const [searchTerm, setSearchTerm] = useState("");
  const [engineFilter, setEngineFilter] = useState("all");
  const [statusFilter, setStatusFilter] = useState("all");
  const [postureFilter, setPostureFilter] = useState("all");

  // Inspect Details Modal state
  const [inspectModal, setInspectModal] = useState({
    isOpen: false,
    instance: null,
  });

  // Action / Mutation Modal state
  const [actionModal, setActionModal] = useState({
    isOpen: false,
    instance: null,
    action: null, // "start" | "stop" | "reboot" | "disable_public_access" | "enable_deletion_protection"
    actionLabel: "",
  });
  const [actionConfirmed, setActionConfirmed] = useState(false);
  const [actionExecuting, setActionExecuting] = useState(false);
  const [actionFeedback, setActionFeedback] = useState(null);

  // Stale request guard ref
  const latestRequestIdRef = useRef(0);

  // ============================================================
  // LOAD CONNECTED ACCOUNTS
  // ============================================================
  useEffect(() => {
    let isMounted = true;

    async function loadAccounts() {
      try {
        setAccountsLoading(true);
        const data = await getAWSAccounts();
        const accList = Array.isArray(data) ? data : [];

        if (!isMounted) return;
        setAccounts(accList);

        if (accList.length > 0) {
          const first = accList[0];
          const accId = first._id || first.aws_account_id || first.account;
          setSelectedAccountId(accId);
          setSelectedRegion(first.region || "us-east-1");
        }
      } catch (err) {
        if (!isMounted) return;
        setError(
          err?.response?.data?.detail ||
            err?.message ||
            "Failed to load connected AWS accounts."
        );
      } finally {
        if (isMounted) {
          setAccountsLoading(false);
        }
      }
    }

    loadAccounts();

    return () => {
      isMounted = false;
    };
  }, []);

  // ============================================================
  // FETCH RDS INVENTORY
  // ============================================================
  const fetchInventory = useCallback(
    async (token = null) => {
      if (!selectedAccountId) return;

      const requestId = ++latestRequestIdRef.current;
      setLoading(true);
      setError(null);

      try {
        const params = {
          region: selectedRegion,
          max_records: pageSize,
        };
        if (token) {
          params.marker = token;
        }
        if (searchTerm.trim()) {
          params.search = searchTerm.trim();
        }
        if (engineFilter !== "all") {
          params.engine = engineFilter;
        }
        if (statusFilter !== "all") {
          params.status = statusFilter;
        }

        const [instData, clustData] = await Promise.allSettled([
          getRDSInstances(selectedAccountId, params),
          getRDSClusters(selectedAccountId, { region: selectedRegion }),
        ]);

        if (requestId !== latestRequestIdRef.current) return;

        if (instData.status === "fulfilled") {
          const d = instData.value;
          setInstances(Array.isArray(d?.instances) ? d.instances : []);
          setTotalCount(d?.total_count || 0);
          setSummary(d?.summary || null);
          setNextToken(d?.next_token || null);
          setCurrentToken(token);
          setLastRefreshed(new Date());
        } else {
          const msg =
            instData.reason?.response?.data?.detail ||
            instData.reason?.message ||
            "Failed to fetch RDS database instances.";
          setError(msg);
          setInstances([]);
          setTotalCount(0);
        }

        if (clustData.status === "fulfilled") {
          setClusters(Array.isArray(clustData.value?.clusters) ? clustData.value.clusters : []);
        } else {
          setClusters([]);
        }
      } finally {
        if (requestId === latestRequestIdRef.current) {
          setLoading(false);
        }
      }
    },
    [selectedAccountId, selectedRegion, pageSize, searchTerm, engineFilter, statusFilter]
  );

  useEffect(() => {
    if (selectedAccountId) {
      setPreviousTokens([]);
      setCurrentToken(null);
      fetchInventory(null);
    }
  }, [selectedAccountId, selectedRegion, fetchInventory]);

  // Pagination handlers
  const handleNextPage = () => {
    if (!nextToken || loading) return;
    setPreviousTokens((prev) => [...prev, currentToken]);
    fetchInventory(nextToken);
  };

  const handlePreviousPage = () => {
    if (previousTokens.length === 0 || loading) return;
    const prevTokensCopy = [...previousTokens];
    const targetToken = prevTokensCopy.pop();
    setPreviousTokens(prevTokensCopy);
    fetchInventory(targetToken);
  };

  // Filtered instances (client-side posture refinement)
  const filteredInstances = useMemo(() => {
    return instances.filter((inst) => {
      if (postureFilter !== "all" && inst.security_posture !== postureFilter) {
        return false;
      }
      return true;
    });
  }, [instances, postureFilter]);

  // Current active account
  const currentAccount = useMemo(() => {
    return (
      accounts.find(
        (a) =>
          a._id === selectedAccountId ||
          a.account_id === selectedAccountId ||
          a.aws_account_id === selectedAccountId
      ) || null
    );
  }, [accounts, selectedAccountId]);

  // ============================================================
  // RDS ACTION MODAL CONTROLS
  // ============================================================
  const openActionModal = (instance, action) => {
    let actionLabel = action.toUpperCase();
    if (action === "start") actionLabel = "Start DB Instance";
    else if (action === "stop") actionLabel = "Stop DB Instance";
    else if (action === "reboot") actionLabel = "Reboot DB Instance";
    else if (action === "disable_public_access") actionLabel = "Disable Public Accessibility";
    else if (action === "enable_deletion_protection") actionLabel = "Enable Deletion Protection";

    setActionModal({
      isOpen: true,
      instance,
      action,
      actionLabel,
    });
    setActionConfirmed(false);
    setActionFeedback(null);
  };

  const closeActionModal = () => {
    if (actionExecuting) return;
    setActionModal({
      isOpen: false,
      instance: null,
      action: null,
      actionLabel: "",
    });
    setActionConfirmed(false);
  };

  const handleExecuteAction = async () => {
    if (!actionModal.instance || !actionModal.action || !actionConfirmed) return;

    setActionExecuting(true);
    setActionFeedback(null);

    try {
      const res = await controlRDSInstance(
        selectedAccountId,
        actionModal.instance.db_instance_identifier,
        {
          action: actionModal.action,
          region: actionModal.instance.region || selectedRegion,
          confirmed: true,
        }
      );

      setActionFeedback({
        type: "success",
        message:
          res.message ||
          `Successfully executed '${actionModal.action}' on '${actionModal.instance.db_instance_identifier}'. Verification: ${res.verification_status}.`,
      });

      closeActionModal();
      fetchInventory(currentToken);
    } catch (err) {
      const errMsg =
        err?.response?.data?.detail ||
        err?.message ||
        `Failed to execute ${actionModal.actionLabel}.`;

      setActionFeedback({
        type: "error",
        message: errMsg,
      });
    } finally {
      setActionExecuting(false);
    }
  };

  // ============================================================
  // BADGE RENDERERS
  // ============================================================
  const renderStatusBadge = (status) => {
    const s = (status || "unknown").toLowerCase();
    if (s === "available") {
      return (
        <span className="rds-badge badge-available">
          <Activity size={12} />
          <span>Available</span>
        </span>
      );
    }
    if (s === "stopped") {
      return (
        <span className="rds-badge badge-stopped">
          <Square size={12} />
          <span>Stopped</span>
        </span>
      );
    }
    if (s === "starting" || s === "stopping" || s === "rebooting" || s === "modifying") {
      return (
        <span className="rds-badge badge-transitioning">
          <RefreshCw size={12} className="spin" />
          <span>{status}</span>
        </span>
      );
    }
    return (
      <span className="rds-badge badge-neutral">
        <span>{status}</span>
      </span>
    );
  };

  const renderPostureBadge = (posture) => {
    switch (posture) {
      case "SECURE":
        return (
          <span className="rds-badge badge-secure">
            <ShieldCheck size={12} />
            <span>SECURE</span>
          </span>
        );
      case "CRITICAL":
        return (
          <span className="rds-badge badge-critical" title="Publicly accessible database instance!">
            <AlertCircle size={12} />
            <span>CRITICAL</span>
          </span>
        );
      case "RISK":
        return (
          <span className="rds-badge badge-risk" title="Storage unencrypted or backup retention is 0">
            <AlertTriangle size={12} />
            <span>RISK</span>
          </span>
        );
      default:
        return (
          <span className="rds-badge badge-neutral">
            <Info size={12} />
            <span>{posture || "EVALUATED"}</span>
          </span>
        );
    }
  };

  return (
    <div className="rds-resources-page">
      {/* Header */}
      <header className="rds-page-header">
        <div className="rds-header-left">
          <div className="rds-icon-badge">
            <HardDrive size={24} />
          </div>
          <div>
            <h1 className="rds-page-title">RDS Database Management</h1>
            <p className="rds-page-subtitle">
              Live AWS RDS instance & cluster discovery, security posture analysis, and safe operational controls.
            </p>
          </div>
        </div>

        <div className="rds-header-actions">
          <button
            type="button"
            className="rds-btn rds-btn-refresh"
            onClick={() => fetchInventory(currentToken)}
            disabled={loading || accountsLoading || !selectedAccountId}
            aria-label="Refresh RDS inventory"
          >
            <RefreshCw size={16} className={loading ? "spin" : ""} />
            <span>{loading ? "Scanning..." : "Refresh"}</span>
          </button>
        </div>
      </header>

      {/* Controls Bar */}
      <section className="rds-controls-bar" aria-label="Filters and account selector">
        {/* Account Selector */}
        <div className="rds-control-group account-group">
          <label htmlFor={accountSelectId} className="control-label">
            AWS Account
          </label>
          <div className="select-wrapper">
            <select
              id={accountSelectId}
              value={selectedAccountId}
              onChange={(e) => setSelectedAccountId(e.target.value)}
              disabled={accountsLoading || accounts.length === 0}
              className="rds-select"
            >
              {accountsLoading ? (
                <option value="">Loading accounts...</option>
              ) : accounts.length === 0 ? (
                <option value="">No connected accounts found</option>
              ) : (
                accounts.map((acc) => {
                  const accId = acc._id || acc.aws_account_id || acc.account;
                  return (
                    <option key={accId} value={accId}>
                      {acc.account_name || "AWS Account"} ({acc.aws_account_id || acc.account || "ID"})
                    </option>
                  );
                })
              )}
            </select>
          </div>
        </div>

        {/* Region Selector */}
        <div className="rds-control-group region-group">
          <label htmlFor={regionSelectId} className="control-label">
            Region
          </label>
          <div className="select-wrapper">
            <select
              id={regionSelectId}
              value={selectedRegion}
              onChange={(e) => setSelectedRegion(e.target.value)}
              className="rds-select"
            >
              {STANDARD_AWS_REGIONS.map((r) => (
                <option key={r.id} value={r.id}>
                  {r.name}
                </option>
              ))}
            </select>
          </div>
        </div>

        {/* Engine Filter */}
        <div className="rds-control-group engine-group">
          <label htmlFor={engineFilterId} className="control-label">
            Engine
          </label>
          <div className="select-wrapper">
            <select
              id={engineFilterId}
              value={engineFilter}
              onChange={(e) => setEngineFilter(e.target.value)}
              className="rds-select"
            >
              <option value="all">All Engines</option>
              <option value="postgres">PostgreSQL</option>
              <option value="mysql">MySQL</option>
              <option value="aurora">Aurora</option>
              <option value="mariadb">MariaDB</option>
              <option value="oracle">Oracle</option>
              <option value="sqlserver">SQL Server</option>
            </select>
          </div>
        </div>

        {/* Status Filter */}
        <div className="rds-control-group status-group">
          <label htmlFor={statusFilterId} className="control-label">
            Status
          </label>
          <div className="select-wrapper">
            <select
              id={statusFilterId}
              value={statusFilter}
              onChange={(e) => setStatusFilter(e.target.value)}
              className="rds-select"
            >
              <option value="all">All States</option>
              <option value="available">Available</option>
              <option value="stopped">Stopped</option>
              <option value="modifying">Modifying</option>
              <option value="backing-up">Backing-up</option>
            </select>
          </div>
        </div>

        {/* Posture Filter */}
        <div className="rds-control-group posture-group">
          <label htmlFor={postureFilterId} className="control-label">
            Security Posture
          </label>
          <div className="select-wrapper">
            <select
              id={postureFilterId}
              value={postureFilter}
              onChange={(e) => setPostureFilter(e.target.value)}
              className="rds-select"
            >
              <option value="all">All Postures</option>
              <option value="SECURE">Secure (Hardened)</option>
              <option value="RISK">Risk (Unencrypted / No Backups)</option>
              <option value="CRITICAL">Critical (Publicly Exposed)</option>
            </select>
          </div>
        </div>

        {/* Search */}
        <div className="rds-control-group search-group">
          <label htmlFor={searchInputId} className="control-label">
            Search
          </label>
          <div className="search-input-wrapper">
            <Search size={16} className="search-icon" />
            <input
              id={searchInputId}
              type="text"
              placeholder="Search by DB identifier or engine..."
              value={searchTerm}
              onChange={(e) => setSearchTerm(e.target.value)}
              className="rds-input search-input"
            />
          </div>
        </div>
      </section>

      {/* Feedback Banner */}
      {actionFeedback && (
        <div
          className={`rds-feedback-banner ${
            actionFeedback.type === "success" ? "feedback-success" : "feedback-error"
          }`}
          role="status"
        >
          {actionFeedback.type === "success" ? (
            <CheckCircle2 size={18} className="feedback-icon" />
          ) : (
            <AlertTriangle size={18} className="feedback-icon" />
          )}
          <div className="feedback-content">
            <p>{actionFeedback.message}</p>
          </div>
          <button
            type="button"
            className="feedback-dismiss-btn"
            onClick={() => setActionFeedback(null)}
            aria-label="Dismiss feedback"
          >
            <X size={15} />
          </button>
        </div>
      )}

      {/* Error State Banner */}
      {error && (
        <div className="rds-error-banner" role="alert">
          <div className="error-icon-box">
            <AlertTriangle size={18} />
          </div>
          <div className="error-content">
            <h4>Failed to Load RDS Inventory</h4>
            <p>{error}</p>
          </div>
          <button
            type="button"
            className="error-retry-btn"
            onClick={() => fetchInventory(currentToken)}
          >
            Retry
          </button>
        </div>
      )}

      {/* Stats Summary Cards */}
      <section className="rds-stats-grid" aria-label="RDS Statistics">
        <div className="rds-stat-card total">
          <div className="stat-icon-wrapper">
            <HardDrive size={20} />
          </div>
          <div className="stat-info">
            <span className="stat-label">Total Instances</span>
            <span className="stat-value">{summary?.total_instances ?? totalCount}</span>
          </div>
        </div>

        <div className="rds-stat-card available">
          <div className="stat-icon-wrapper">
            <Activity size={20} />
          </div>
          <div className="stat-info">
            <span className="stat-label">Available / Running</span>
            <span className="stat-value">{summary?.available_instances ?? 0}</span>
          </div>
        </div>

        <div className="rds-stat-card stopped">
          <div className="stat-icon-wrapper">
            <Square size={20} />
          </div>
          <div className="stat-info">
            <span className="stat-label">Stopped</span>
            <span className="stat-value">{summary?.stopped_instances ?? 0}</span>
          </div>
        </div>

        <div className="rds-stat-card public">
          <div className="stat-icon-wrapper">
            <Unlock size={20} />
          </div>
          <div className="stat-info">
            <span className="stat-label">Publicly Exposed</span>
            <span className="stat-value">{summary?.publicly_accessible ?? 0}</span>
          </div>
        </div>

        <div className="rds-stat-card encrypted">
          <div className="stat-icon-wrapper">
            <Key size={20} />
          </div>
          <div className="stat-info">
            <span className="stat-label">Encrypted at Rest</span>
            <span className="stat-value">{summary?.encrypted_instances ?? 0}</span>
          </div>
        </div>

        <div className="rds-stat-card clusters">
          <div className="stat-icon-wrapper">
            <Layers size={20} />
          </div>
          <div className="stat-info">
            <span className="stat-label">DB Clusters</span>
            <span className="stat-value">{clusters.length}</span>
          </div>
        </div>
      </section>

      {/* DB Instances Table */}
      <section className="rds-table-container" aria-label="RDS DB Instances Table">
        <div className="rds-table-header-row">
          <div className="table-header-left">
            <h3 className="table-title">DB Instances</h3>
            <span className="table-count-badge">
              {filteredInstances.length} of {totalCount}
            </span>
            {lastRefreshed && (
              <span className="last-refreshed-text">
                • Region: {selectedRegion} • Updated: {lastRefreshed.toLocaleTimeString()}
              </span>
            )}
          </div>
        </div>

        <div className="rds-table-scroll-wrapper">
          <table className="rds-table">
            <thead>
              <tr>
                <th scope="col">DB Identifier</th>
                <th scope="col">Engine & Version</th>
                <th scope="col">Class</th>
                <th scope="col">Status</th>
                <th scope="col">Deployment</th>
                <th scope="col">Public Access</th>
                <th scope="col">Encryption</th>
                <th scope="col">Security Posture</th>
                <th scope="col" className="text-right">Actions</th>
              </tr>
            </thead>
            <tbody>
              {loading ? (
                <tr>
                  <td colSpan="9" className="table-loading-cell">
                    <div className="loading-spinner-wrap">
                      <RefreshCw size={24} className="spin" />
                      <span>Discovering RDS instances and evaluating security posture in {selectedRegion}...</span>
                    </div>
                  </td>
                </tr>
              ) : filteredInstances.length === 0 ? (
                <tr>
                  <td colSpan="9" className="table-empty-cell">
                    <div className="empty-state-wrap">
                      <HardDrive size={36} className="empty-icon" />
                      <h4>No RDS DB Instances Found</h4>
                      <p>
                        {searchTerm || engineFilter !== "all" || statusFilter !== "all"
                          ? "No database instances match the selected filter criteria."
                          : `No RDS database instances discovered in ${selectedRegion}.`}
                      </p>
                    </div>
                  </td>
                </tr>
              ) : (
                filteredInstances.map((db) => {
                  const isAvailable = db.status === "available";
                  const isStopped = db.status === "stopped";
                  const isPublic = db.publicly_accessible;
                  const isCluster = db.is_cluster_member;

                  return (
                    <tr key={db.db_instance_identifier} className="rds-row">
                      <td className="db-name-cell">
                        <div className="db-name-wrap">
                          <Database size={16} className="db-item-icon" />
                          <div>
                            <span className="db-name-text">{db.db_instance_identifier}</span>
                            {db.cluster_identifier && (
                              <span className="db-cluster-badge">
                                Cluster: {db.cluster_identifier}
                              </span>
                            )}
                          </div>
                        </div>
                      </td>
                      <td>
                        <span className="engine-text">{db.engine}</span>
                        {db.engine_version && (
                          <span className="engine-version-subtext">v{db.engine_version}</span>
                        )}
                      </td>
                      <td>
                        <span className="mono-text">{db.instance_class || "-"}</span>
                      </td>
                      <td>{renderStatusBadge(db.status)}</td>
                      <td>
                        <div className="deployment-cell">
                          <span className="az-text">{db.availability_zone || db.region}</span>
                          {db.multi_az && <span className="multiaz-badge">Multi-AZ</span>}
                        </div>
                      </td>
                      <td>
                        {isPublic ? (
                          <span className="rds-badge badge-critical">
                            <Unlock size={12} />
                            <span>Public (Risk)</span>
                          </span>
                        ) : (
                          <span className="rds-badge badge-secure">
                            <Lock size={12} />
                            <span>Private</span>
                          </span>
                        )}
                      </td>
                      <td>
                        {db.storage_encrypted ? (
                          <span className="rds-badge badge-secure">
                            <Key size={12} />
                            <span>Encrypted</span>
                          </span>
                        ) : (
                          <span className="rds-badge badge-risk">
                            <AlertTriangle size={12} />
                            <span>Disabled</span>
                          </span>
                        )}
                      </td>
                      <td>{renderPostureBadge(db.security_posture)}</td>
                      <td className="actions-cell text-right">
                        <div className="action-buttons-group">
                          {/* Inspect Details Button */}
                          <button
                            type="button"
                            className="rds-btn-action btn-inspect"
                            onClick={() => setInspectModal({ isOpen: true, instance: db })}
                            title="Inspect complete configuration & endpoints"
                          >
                            <Eye size={14} />
                            <span>Inspect</span>
                          </button>

                          {/* Operational Controls (Standalone only) */}
                          {!isCluster && isStopped && (
                            <button
                              type="button"
                              className="rds-btn-action btn-start"
                              onClick={() => openActionModal(db, "start")}
                              title="Start stopped DB instance"
                            >
                              <Play size={14} />
                              <span>Start</span>
                            </button>
                          )}

                          {!isCluster && isAvailable && (
                            <button
                              type="button"
                              className="rds-btn-action btn-stop"
                              onClick={() => openActionModal(db, "stop")}
                              title="Stop running DB instance"
                            >
                              <Square size={14} />
                              <span>Stop</span>
                            </button>
                          )}

                          {isAvailable && (
                            <button
                              type="button"
                              className="rds-btn-action btn-reboot"
                              onClick={() => openActionModal(db, "reboot")}
                              title="Reboot DB instance"
                            >
                              <RotateCw size={14} />
                              <span>Reboot</span>
                            </button>
                          )}

                          {/* Security Remediations */}
                          {isPublic && (
                            <button
                              type="button"
                              className="rds-btn-action btn-remediate"
                              onClick={() => openActionModal(db, "disable_public_access")}
                              title="Remediate: Disable public accessibility"
                            >
                              <Lock size={14} />
                              <span>Make Private</span>
                            </button>
                          )}
                        </div>
                      </td>
                    </tr>
                  );
                })
              )}
            </tbody>
          </table>
        </div>

        {/* Pagination Bar */}
        <div className="rds-pagination-bar">
          <div className="pagination-info">
            <span>
              Showing {filteredInstances.length} of {totalCount} database instances in {selectedRegion}
            </span>
          </div>

          <div className="pagination-controls">
            <button
              type="button"
              className="pagination-btn"
              onClick={handlePreviousPage}
              disabled={previousTokens.length === 0 || loading}
              aria-label="Previous page"
            >
              <ChevronLeft size={16} />
              <span>Previous</span>
            </button>
            <button
              type="button"
              className="pagination-btn"
              onClick={handleNextPage}
              disabled={!nextToken || loading}
              aria-label="Next page"
            >
              <span>Next</span>
              <ChevronRight size={16} />
            </button>
          </div>
        </div>
      </section>

      {/* Inspect Database Details Modal */}
      {inspectModal.isOpen && inspectModal.instance && (
        <div className="rds-modal-overlay" role="dialog" aria-modal="true">
          <div className="rds-modal-card inspect-modal-card">
            <div className="rds-modal-header">
              <div className="modal-title-wrap">
                <Database size={22} className="text-sky" />
                <div>
                  <h3>RDS Configuration: {inspectModal.instance.db_instance_identifier}</h3>
                  <span className="modal-sub-region">
                    Engine: {inspectModal.instance.engine} v{inspectModal.instance.engine_version} • Region: {inspectModal.instance.region}
                  </span>
                </div>
              </div>
              <button
                type="button"
                className="modal-close-btn"
                onClick={() => setInspectModal({ isOpen: false, instance: null })}
                aria-label="Close dialog"
              >
                <X size={18} />
              </button>
            </div>

            <div className="rds-modal-body">
              {/* Networking & Endpoints */}
              <div className="posture-section">
                <h4 className="section-title">
                  <Network size={16} /> Networking & Endpoint
                </h4>
                <div className="posture-grid">
                  <div className="posture-item full-width">
                    <span className="item-label">Endpoint Hostname & Port</span>
                    <span className="item-val mono font-semibold">
                      {inspectModal.instance.endpoint
                        ? `${inspectModal.instance.endpoint.address}:${inspectModal.instance.endpoint.port}`
                        : "No active endpoint"}
                    </span>
                  </div>
                  <div className="posture-item">
                    <span className="item-label">VPC ID</span>
                    <span className="item-val mono">{inspectModal.instance.vpc_id || "Default VPC"}</span>
                  </div>
                  <div className="posture-item">
                    <span className="item-label">Subnet Group</span>
                    <span className="item-val">{inspectModal.instance.subnet_group_name || "-"}</span>
                  </div>
                </div>
              </div>

              {/* Security & Encryption */}
              <div className="posture-section">
                <h4 className="section-title">
                  <ShieldCheck size={16} /> Security, Storage & Encryption
                </h4>
                <div className="posture-grid">
                  <div className="posture-item">
                    <span className="item-label">Public Accessibility</span>
                    <span className="item-val">
                      {inspectModal.instance.publicly_accessible ? (
                        <span className="text-rose font-semibold">PUBLICLY ACCESSIBLE (CRITICAL)</span>
                      ) : (
                        <span className="text-emerald font-semibold">Private (Protected)</span>
                      )}
                    </span>
                  </div>
                  <div className="posture-item">
                    <span className="item-label">Storage Encryption</span>
                    <span className="item-val">
                      {inspectModal.instance.storage_encrypted ? (
                        <span className="text-emerald font-semibold">KMS Encrypted</span>
                      ) : (
                        <span className="text-amber font-semibold">Disabled / Unencrypted</span>
                      )}
                    </span>
                  </div>
                  <div className="posture-item">
                    <span className="item-label">Deletion Protection</span>
                    <span className="item-val">
                      {inspectModal.instance.deletion_protection ? (
                        <span className="text-emerald font-semibold">Enabled</span>
                      ) : (
                        <span className="text-slate-400">Disabled</span>
                      )}
                    </span>
                  </div>
                  <div className="posture-item">
                    <span className="item-label">Backup Retention Period</span>
                    <span className="item-val">
                      {inspectModal.instance.backup_retention_period > 0 ? (
                        <span className="text-emerald font-semibold">
                          {inspectModal.instance.backup_retention_period} Days
                        </span>
                      ) : (
                        <span className="text-rose font-semibold">Backups Disabled (0 Days)</span>
                      )}
                    </span>
                  </div>
                </div>
              </div>

              {/* High Availability & Monitoring */}
              <div className="posture-section">
                <h4 className="section-title">
                  <Layers size={16} /> Availability & Maintenance
                </h4>
                <div className="posture-grid">
                  <div className="posture-item">
                    <span className="item-label">Multi-AZ Deployment</span>
                    <span className="item-val">
                      {inspectModal.instance.multi_az ? "Multi-AZ Synchronous Replication" : "Single-AZ"}
                    </span>
                  </div>
                  <div className="posture-item">
                    <span className="item-label">Auto Minor Version Upgrade</span>
                    <span className="item-val">
                      {inspectModal.instance.auto_minor_version_upgrade ? "Enabled" : "Disabled"}
                    </span>
                  </div>
                  <div className="posture-item">
                    <span className="item-label">Allocated Storage</span>
                    <span className="item-val">
                      {inspectModal.instance.allocated_storage ? `${inspectModal.instance.allocated_storage} GB (${inspectModal.instance.storage_type || "gp2"})` : "-"}
                    </span>
                  </div>
                  <div className="posture-item">
                    <span className="item-label">Latest Restorable Time</span>
                    <span className="item-val">
                      {inspectModal.instance.latest_restorable_time
                        ? new Date(inspectModal.instance.latest_restorable_time).toLocaleString()
                        : "-"}
                    </span>
                  </div>
                </div>
              </div>
            </div>

            <div className="rds-modal-footer">
              <button
                type="button"
                className="modal-btn-cancel"
                onClick={() => setInspectModal({ isOpen: false, instance: null })}
              >
                Close
              </button>
            </div>
          </div>
        </div>
      )}

      {/* Explicit Confirmation Dialog Modal */}
      {actionModal.isOpen && actionModal.instance && (
        <div className="rds-modal-overlay" role="dialog" aria-modal="true">
          <div className="rds-modal-card">
            <div className="rds-modal-header">
              <div className="modal-title-wrap">
                <AlertTriangle size={20} className="text-amber" />
                <h3>Confirm RDS {actionModal.actionLabel}</h3>
              </div>
              <button
                type="button"
                className="modal-close-btn"
                onClick={closeActionModal}
                disabled={actionExecuting}
                aria-label="Close dialog"
              >
                <X size={18} />
              </button>
            </div>

            <div className="rds-modal-body">
              <p className="modal-description">
                You are about to execute an audited action on the target database: <strong>{actionModal.actionLabel}</strong>.
              </p>

              <div className="modal-context-box">
                <div className="context-row">
                  <span className="context-label">DB Identifier:</span>
                  <span className="context-value mono">{actionModal.instance.db_instance_identifier}</span>
                </div>
                <div className="context-row">
                  <span className="context-label">AWS Account:</span>
                  <span className="context-value">
                    {currentAccount?.account_name || selectedAccountId} (
                    {currentAccount?.aws_account_id || currentAccount?.account || "-"})
                  </span>
                </div>
                <div className="context-row">
                  <span className="context-label">Region & AZ:</span>
                  <span className="context-value mono">
                    {actionModal.instance.region || selectedRegion} ({actionModal.instance.availability_zone || "-"})
                  </span>
                </div>
                <div className="context-row">
                  <span className="context-label">Current Status:</span>
                  <span className="context-value">{renderStatusBadge(actionModal.instance.status)}</span>
                </div>
              </div>

              {actionModal.action === "stop" && (
                <div className="modal-warning-notice">
                  <AlertTriangle size={16} />
                  <span>
                    Stopping this database instance will terminate active client connections and cause application downtime until restarted. (AWS automatically restarts stopped DB instances after 7 days).
                  </span>
                </div>
              )}

              {actionModal.action === "reboot" && (
                <div className="modal-warning-notice">
                  <AlertTriangle size={16} />
                  <span>
                    Rebooting will disconnect all database sessions and restart the DB engine. Multi-AZ failover may occur if configured.
                  </span>
                </div>
              )}

              <div className="modal-safety-notice">
                <Shield size={16} />
                <span>
                  This action requires Owner/Admin permissions. It will be recorded in the CloudGuardAI tamper-evident audit log with actor identity and post-action verification.
                </span>
              </div>

              <div className="modal-confirm-checkbox-wrap">
                <input
                  id={confirmCheckId}
                  type="checkbox"
                  checked={actionConfirmed}
                  onChange={(e) => setActionConfirmed(e.target.checked)}
                  disabled={actionExecuting}
                  className="modal-checkbox"
                />
                <label htmlFor={confirmCheckId} className="modal-checkbox-label">
                  I confirm that I want to <strong>{actionModal.action}</strong> database{" "}
                  <code>{actionModal.instance.db_instance_identifier}</code> in{" "}
                  <code>{actionModal.instance.region || selectedRegion}</code>.
                </label>
              </div>
            </div>

            <div className="rds-modal-footer">
              <button
                type="button"
                className="modal-btn-cancel"
                onClick={closeActionModal}
                disabled={actionExecuting}
              >
                Cancel
              </button>
              <button
                type="button"
                className={`modal-btn-execute ${
                  actionModal.action === "stop"
                    ? "btn-modal-stop"
                    : actionModal.action === "start"
                    ? "btn-modal-start"
                    : "btn-modal-action"
                }`}
                onClick={handleExecuteAction}
                disabled={!actionConfirmed || actionExecuting}
              >
                {actionExecuting ? (
                  <>
                    <RefreshCw size={14} className="spin" />
                    <span>Executing...</span>
                  </>
                ) : (
                  <span>Execute {actionModal.action?.toUpperCase()}</span>
                )}
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
