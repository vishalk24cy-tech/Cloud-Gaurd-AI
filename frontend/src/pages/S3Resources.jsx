import { useCallback, useEffect, useId, useMemo, useRef, useState } from "react";
import { Link } from "react-router-dom";
import {
  Database,
  RefreshCw,
  Search,
  AlertTriangle,
  ChevronLeft,
  ChevronRight,
  Shield,
  ShieldCheck,
  CheckCircle2,
  AlertCircle,
  Clock,
  Layers,
  Lock,
  Unlock,
  Key,
  History,
  FileCode,
  X,
  Eye,
  Info,
  ExternalLink,
} from "lucide-react";
import {
  getAWSAccounts,
  getS3Buckets,
  controlS3Bucket,
} from "../services/awsService";
import "./S3Resources.css";

const STANDARD_AWS_REGIONS = [
  { id: "all", name: "All Regions (Account Global View)" },
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

export default function S3Resources() {
  const accountSelectId = useId();
  const regionSelectId = useId();
  const searchInputId = useId();
  const postureFilterId = useId();
  const confirmCheckId = useId();

  // Accounts state
  const [accounts, setAccounts] = useState([]);
  const [accountsLoading, setAccountsLoading] = useState(true);
  const [selectedAccountId, setSelectedAccountId] = useState("");

  // Inventory & Posture state
  const [selectedRegion, setSelectedRegion] = useState("all");
  const [buckets, setBuckets] = useState([]);
  const [summary, setSummary] = useState(null);
  const [totalCount, setTotalCount] = useState(0);
  const [coverage, setCoverage] = useState("COMPLETE");
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState(null);
  const [lastRefreshed, setLastRefreshed] = useState(null);

  // Pagination state
  const [nextToken, setNextToken] = useState(null);
  const [previousTokens, setPreviousTokens] = useState([]);
  const [currentToken, setCurrentToken] = useState(null);
  const [pageSize, setPageSize] = useState(50);

  // Search & filter
  const [searchTerm, setSearchTerm] = useState("");
  const [postureFilter, setPostureFilter] = useState("all");

  // Inspect Posture Details Modal state
  const [inspectModal, setInspectModal] = useState({
    isOpen: false,
    bucket: null,
  });

  // Action / Mutation Modal state
  const [actionModal, setActionModal] = useState({
    isOpen: false,
    bucket: null,
    action: null, // "enable_block_public_access" | "enable_encryption" | "enable_versioning"
    actionLabel: "",
  });
  const [actionConfirmed, setActionConfirmed] = useState(false);
  const [actionExecuting, setActionExecuting] = useState(false);
  const [actionFeedback, setActionFeedback] = useState(null); // { type: 'success'|'error', message: '' }

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
        }
      } catch (err) {
        if (!isMounted) return;
        setError(
          err?.response?.data?.detail ||
            err?.message ||
            "Failed to load connected AWS accounts. Ensure your session is valid."
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
  // FETCH S3 BUCKET INVENTORY & POSTURE
  // ============================================================
  const fetchInventory = useCallback(
    async (token = null) => {
      if (!selectedAccountId) return;

      const requestId = ++latestRequestIdRef.current;
      setLoading(true);
      setError(null);

      try {
        const params = {
          page_size: pageSize,
        };
        if (selectedRegion && selectedRegion !== "all") {
          params.region = selectedRegion;
        }
        if (token) {
          params.next_token = token;
        }
        if (searchTerm.trim()) {
          params.search = searchTerm.trim();
        }

        const data = await getS3Buckets(selectedAccountId, params);

        // Guard against stale asynchronous responses
        if (requestId !== latestRequestIdRef.current) return;

        setBuckets(Array.isArray(data?.buckets) ? data.buckets : []);
        setTotalCount(data?.total_count || 0);
        setSummary(data?.summary || null);
        setCoverage(data?.coverage || "COMPLETE");
        setNextToken(data?.next_token || null);
        setCurrentToken(token);
        setLastRefreshed(new Date());
      } catch (err) {
        if (requestId !== latestRequestIdRef.current) return;
        const msg =
          err?.response?.data?.detail ||
          err?.message ||
          "Failed to fetch S3 bucket inventory from AWS.";
        setError(msg);
        setBuckets([]);
        setTotalCount(0);
      } finally {
        if (requestId === latestRequestIdRef.current) {
          setLoading(false);
        }
      }
    },
    [selectedAccountId, selectedRegion, pageSize, searchTerm]
  );

  // Trigger fetch whenever selected account, region, or search changes
  useEffect(() => {
    if (selectedAccountId) {
      setPreviousTokens([]);
      setCurrentToken(null);
      fetchInventory(null);
    }
  }, [selectedAccountId, selectedRegion, fetchInventory]);

  // ============================================================
  // PAGINATION HANDLERS
  // ============================================================
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

  // ============================================================
  // FILTERED BUCKETS
  // ============================================================
  const filteredBuckets = useMemo(() => {
    return buckets.filter((b) => {
      // Search filter (client-side refinement)
      if (searchTerm.trim()) {
        const query = searchTerm.toLowerCase().trim();
        const matchesName = b.bucket_name?.toLowerCase().includes(query);
        const matchesRegion = b.region?.toLowerCase().includes(query);
        if (!matchesName && !matchesRegion) return false;
      }

      // Posture filter
      if (postureFilter !== "all") {
        if (postureFilter === "SECURE" && b.security_posture !== "SECURE") return false;
        if (postureFilter === "RISK" && b.security_posture !== "RISK") return false;
        if (postureFilter === "CRITICAL" && b.security_posture !== "CRITICAL") return false;
        if (postureFilter === "PARTIAL" && b.coverage !== "PARTIAL") return false;
      }

      return true;
    });
  }, [buckets, searchTerm, postureFilter]);

  // Current active account object
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
  // S3 MUTATION CONTROLS (ENABLE BPA / ENCRYPTION / VERSIONING)
  // ============================================================
  const openActionModal = (bucket, action) => {
    let actionLabel = "Security Control";
    if (action === "enable_block_public_access") {
      actionLabel = "Enable S3 Block Public Access";
    } else if (action === "enable_encryption") {
      actionLabel = "Enable Default AES-256 SSE Encryption";
    } else if (action === "enable_versioning") {
      actionLabel = "Enable S3 Bucket Versioning";
    }

    setActionModal({
      isOpen: true,
      bucket,
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
      bucket: null,
      action: null,
      actionLabel: "",
    });
    setActionConfirmed(false);
  };

  const handleExecuteAction = async () => {
    if (!actionModal.bucket || !actionModal.action || !actionConfirmed) return;

    setActionExecuting(true);
    setActionFeedback(null);

    try {
      const res = await controlS3Bucket(
        selectedAccountId,
        actionModal.bucket.bucket_name,
        {
          action: actionModal.action,
          region: actionModal.bucket.region,
          confirmed: true,
        }
      );

      setActionFeedback({
        type: "success",
        message:
          res.message ||
          `Successfully applied ${actionModal.actionLabel} to '${actionModal.bucket.bucket_name}'. Post-state verification: ${res.verification_status}.`,
      });

      closeActionModal();
      // Refresh inventory from backend
      fetchInventory(currentToken);
    } catch (err) {
      const errMsg =
        err?.response?.data?.detail ||
        err?.message ||
        `Failed to execute ${actionModal.actionLabel} on bucket '${actionModal.bucket.bucket_name}'.`;

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
  const renderPostureBadge = (posture, cov) => {
    if (cov === "PARTIAL" || posture === "UNKNOWN") {
      return (
        <span className="s3-badge badge-warning" title="Partial inspection or unverified settings">
          <AlertTriangle size={12} />
          <span>PARTIAL</span>
        </span>
      );
    }
    switch (posture) {
      case "SECURE":
        return (
          <span className="s3-badge badge-secure">
            <ShieldCheck size={12} />
            <span>SECURE</span>
          </span>
        );
      case "CRITICAL":
        return (
          <span className="s3-badge badge-critical">
            <AlertCircle size={12} />
            <span>CRITICAL</span>
          </span>
        );
      case "RISK":
        return (
          <span className="s3-badge badge-risk">
            <AlertTriangle size={12} />
            <span>RISK</span>
          </span>
        );
      default:
        return (
          <span className="s3-badge badge-neutral">
            <Info size={12} />
            <span>{posture || "EVALUATED"}</span>
          </span>
        );
    }
  };

  const renderBpaBadge = (bpa) => {
    if (!bpa || !bpa.verified) {
      return <span className="s3-badge badge-neutral">UNVERIFIED</span>;
    }
    if (bpa.all_protected) {
      return (
        <span className="s3-badge badge-secure" title="All 4 Block Public Access flags enabled">
          <Lock size={12} />
          <span>PROTECTED</span>
        </span>
      );
    }
    if (bpa.configured) {
      return (
        <span className="s3-badge badge-warning" title="Some public access settings are not blocked">
          <Unlock size={12} />
          <span>PARTIAL</span>
        </span>
      );
    }
    return (
      <span className="s3-badge badge-risk" title="Block Public Access is not configured">
        <Unlock size={12} />
        <span>DISABLED</span>
      </span>
    );
  };

  const renderEncryptionBadge = (enc) => {
    if (!enc || !enc.verified) {
      return <span className="s3-badge badge-neutral">UNVERIFIED</span>;
    }
    if (enc.enabled) {
      return (
        <span className="s3-badge badge-secure" title={`SSE Enabled: ${enc.algorithm || "AES256"}`}>
          <Key size={12} />
          <span>{enc.algorithm || "ENABLED"}</span>
        </span>
      );
    }
    return (
      <span className="s3-badge badge-risk" title="Server-Side Encryption is disabled or not configured">
        <AlertTriangle size={12} />
        <span>DISABLED</span>
      </span>
    );
  };

  const renderVersioningBadge = (ver) => {
    if (!ver || !ver.verified) {
      return <span className="s3-badge badge-neutral">UNVERIFIED</span>;
    }
    if (ver.enabled) {
      return (
        <span className="s3-badge badge-secure">
          <History size={12} />
          <span>ENABLED</span>
        </span>
      );
    }
    return (
      <span className="s3-badge badge-neutral">
        <span>{ver.status || "DISABLED"}</span>
      </span>
    );
  };

  return (
    <div className="s3-resources-page">
      {/* Header */}
      <header className="s3-page-header">
        <div className="s3-header-left">
          <div className="s3-icon-badge">
            <Database size={24} />
          </div>
          <div>
            <h1 className="s3-page-title">S3 Resource Management</h1>
            <p className="s3-page-subtitle">
              Live S3 bucket inventory, security posture analysis, and explicit remediation controls.
            </p>
          </div>
        </div>

        <div className="s3-header-actions">
          <button
            type="button"
            className="s3-btn s3-btn-refresh"
            onClick={() => fetchInventory(currentToken)}
            disabled={loading || accountsLoading || !selectedAccountId}
            aria-label="Refresh S3 inventory"
          >
            <RefreshCw size={16} className={loading ? "spin" : ""} />
            <span>{loading ? "Scanning..." : "Refresh"}</span>
          </button>
        </div>
      </header>

      {/* Control Bar: Account, Region, Posture Filter, Search */}
      <section className="s3-controls-bar" aria-label="Filters and account selector">
        {/* Account Selector */}
        <div className="s3-control-group account-group">
          <label htmlFor={accountSelectId} className="control-label">
            AWS Account
          </label>
          <div className="select-wrapper">
            <select
              id={accountSelectId}
              value={selectedAccountId}
              onChange={(e) => setSelectedAccountId(e.target.value)}
              disabled={accountsLoading || accounts.length === 0}
              className="s3-select"
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

        {/* Region Filter */}
        <div className="s3-control-group region-group">
          <label htmlFor={regionSelectId} className="control-label">
            Region
          </label>
          <div className="select-wrapper">
            <select
              id={regionSelectId}
              value={selectedRegion}
              onChange={(e) => setSelectedRegion(e.target.value)}
              className="s3-select"
            >
              {STANDARD_AWS_REGIONS.map((r) => (
                <option key={r.id} value={r.id}>
                  {r.name}
                </option>
              ))}
            </select>
          </div>
        </div>

        {/* Posture Filter */}
        <div className="s3-control-group posture-group">
          <label htmlFor={postureFilterId} className="control-label">
            Security Posture
          </label>
          <div className="select-wrapper">
            <select
              id={postureFilterId}
              value={postureFilter}
              onChange={(e) => setPostureFilter(e.target.value)}
              className="s3-select"
            >
              <option value="all">All Postures</option>
              <option value="SECURE">Secure (Hardened)</option>
              <option value="RISK">Risk (BPA or SSE Missing)</option>
              <option value="CRITICAL">Critical (Public Exposure)</option>
              <option value="PARTIAL">Partial / Unverified</option>
            </select>
          </div>
        </div>

        {/* Search */}
        <div className="s3-control-group search-group">
          <label htmlFor={searchInputId} className="control-label">
            Search Buckets
          </label>
          <div className="search-input-wrapper">
            <Search size={16} className="search-icon" />
            <input
              id={searchInputId}
              type="text"
              placeholder="Search by bucket name or region..."
              value={searchTerm}
              onChange={(e) => setSearchTerm(e.target.value)}
              className="s3-input search-input"
            />
          </div>
        </div>
      </section>

      {/* Action Execution Feedback Alert */}
      {actionFeedback && (
        <div
          className={`s3-feedback-banner ${
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

      {/* Account Disconnected Warning Banner */}
      {currentAccount && currentAccount.status === "disconnected" && (
        <div className="s3-error-banner" role="alert" style={{ background: "rgba(239, 68, 68, 0.15)", borderColor: "rgba(239, 68, 68, 0.4)" }}>
          <div className="error-icon-box">
            <AlertTriangle size={18} className="text-red" />
          </div>
          <div className="error-content">
            <h4>AWS Account Disconnected</h4>
            <p>This AWS account is marked as disconnected. Reconnect or re-verify STS AssumeRole credentials in <Link to="/connect-aws" style={{ color: "#60a5fa", textDecoration: "underline" }}>Connect AWS</Link> to view live S3 buckets.</p>
          </div>
        </div>
      )}

      {/* Error State Banner */}
      {error && (
        <div className="s3-error-banner" role="alert">
          <div className="error-icon-box">
            <AlertTriangle size={18} />
          </div>
          <div className="error-content">
            <h4>Failed to Load S3 Bucket Inventory</h4>
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
      <section className="s3-stats-grid" aria-label="Bucket Security Statistics">
        <div className="s3-stat-card total">
          <div className="stat-icon-wrapper">
            <Database size={20} />
          </div>
          <div className="stat-info">
            <span className="stat-label">Total Buckets</span>
            <span className="stat-value">{summary?.total_buckets ?? totalCount}</span>
          </div>
        </div>

        <div className="s3-stat-card secure">
          <div className="stat-icon-wrapper">
            <ShieldCheck size={20} />
          </div>
          <div className="stat-info">
            <span className="stat-label">Hardened & Secure</span>
            <span className="stat-value">{summary?.secure_buckets ?? 0}</span>
          </div>
        </div>

        <div className="s3-stat-card bpa">
          <div className="stat-icon-wrapper">
            <Lock size={20} />
          </div>
          <div className="stat-info">
            <span className="stat-label">BPA Protected</span>
            <span className="stat-value">{summary?.protected_bpa_buckets ?? 0}</span>
          </div>
        </div>

        <div className="s3-stat-card encryption">
          <div className="stat-icon-wrapper">
            <Key size={20} />
          </div>
          <div className="stat-info">
            <span className="stat-label">Encrypted (SSE)</span>
            <span className="stat-value">{summary?.encrypted_buckets ?? 0}</span>
          </div>
        </div>

        <div className="s3-stat-card risk">
          <div className="stat-icon-wrapper">
            <AlertTriangle size={20} />
          </div>
          <div className="stat-info">
            <span className="stat-label">Attention Needed</span>
            <span className="stat-value">
              {(summary?.risk_buckets || 0) + (summary?.critical_buckets || 0)}
            </span>
          </div>
        </div>
      </section>

      {/* Table Section */}
      <section className="s3-table-container" aria-label="S3 Bucket Inventory Table">
        <div className="s3-table-header-row">
          <div className="table-header-left">
            <h3 className="table-title">Discovered Buckets</h3>
            <span className="table-count-badge">
              {filteredBuckets.length} of {totalCount}
            </span>
            {lastRefreshed && (
              <span className="last-refreshed-text">
                • Updated: {lastRefreshed.toLocaleTimeString()}
              </span>
            )}
          </div>
        </div>

        <div className="s3-table-scroll-wrapper">
          <table className="s3-table">
            <thead>
              <tr>
                <th scope="col">Bucket Name</th>
                <th scope="col">Region</th>
                <th scope="col">Block Public Access</th>
                <th scope="col">Encryption</th>
                <th scope="col">Versioning</th>
                <th scope="col">Security Posture</th>
                <th scope="col" className="text-right">Actions</th>
              </tr>
            </thead>
            <tbody>
              {loading ? (
                <tr>
                  <td colSpan="7" className="table-loading-cell">
                    <div className="loading-spinner-wrap">
                      <RefreshCw size={24} className="spin" />
                      <span>Inspecting S3 security configurations across regions...</span>
                    </div>
                  </td>
                </tr>
              ) : filteredBuckets.length === 0 ? (
                <tr>
                  <td colSpan="7" className="table-empty-cell">
                    <div className="empty-state-wrap">
                      <Database size={36} className="empty-icon" />
                      <h4>No S3 Buckets Found</h4>
                      <p>
                        {searchTerm || postureFilter !== "all"
                          ? "No buckets match the selected filter criteria."
                          : "No S3 buckets were discovered in this connected AWS account."}
                      </p>
                    </div>
                  </td>
                </tr>
              ) : (
                filteredBuckets.map((bucket) => {
                  const bpaProtected = bucket.block_public_access?.all_protected;
                  const encEnabled = bucket.encryption?.enabled;
                  const verEnabled = bucket.versioning?.enabled;

                  return (
                    <tr key={bucket.bucket_name} className="s3-row">
                      <td className="bucket-name-cell">
                        <div className="bucket-name-wrap">
                          <Database size={16} className="bucket-item-icon" />
                          <div>
                            <span className="bucket-name-text">{bucket.bucket_name}</span>
                            {bucket.creation_date && (
                              <span className="bucket-created-subtext">
                                Created: {new Date(bucket.creation_date).toLocaleDateString()}
                              </span>
                            )}
                          </div>
                        </div>
                      </td>
                      <td>
                        <span className="region-code-badge">{bucket.region || "UNKNOWN"}</span>
                      </td>
                      <td>{renderBpaBadge(bucket.block_public_access)}</td>
                      <td>{renderEncryptionBadge(bucket.encryption)}</td>
                      <td>{renderVersioningBadge(bucket.versioning)}</td>
                      <td>{renderPostureBadge(bucket.security_posture, bucket.coverage)}</td>
                      <td className="actions-cell text-right">
                        <div className="action-buttons-group">
                          {/* Inspect Posture Details Button */}
                          <button
                            type="button"
                            className="s3-btn-action btn-inspect"
                            onClick={() => setInspectModal({ isOpen: true, bucket })}
                            title="Inspect complete security configuration"
                          >
                            <Eye size={14} />
                            <span>Inspect</span>
                          </button>

                          {/* Remediation Quick Actions */}
                          {!bpaProtected && (
                            <button
                              type="button"
                              className="s3-btn-action btn-enable-bpa"
                              onClick={() => openActionModal(bucket, "enable_block_public_access")}
                              title="Enable S3 Block Public Access"
                            >
                              <Lock size={14} />
                              <span>Enable BPA</span>
                            </button>
                          )}

                          {!encEnabled && (
                            <button
                              type="button"
                              className="s3-btn-action btn-enable-enc"
                              onClick={() => openActionModal(bucket, "enable_encryption")}
                              title="Enable default AES-256 SSE encryption"
                            >
                              <Key size={14} />
                              <span>Enable SSE</span>
                            </button>
                          )}

                          {!verEnabled && (
                            <button
                              type="button"
                              className="s3-btn-action btn-enable-ver"
                              onClick={() => openActionModal(bucket, "enable_versioning")}
                              title="Enable S3 bucket versioning"
                            >
                              <History size={14} />
                              <span>Enable Ver.</span>
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
        <div className="s3-pagination-bar">
          <div className="pagination-info">
            <span>
              Showing {filteredBuckets.length} of {totalCount} discovered buckets
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

      {/* Inspect Posture Details Modal */}
      {inspectModal.isOpen && inspectModal.bucket && (
        <div className="s3-modal-overlay" role="dialog" aria-modal="true">
          <div className="s3-modal-card inspect-modal-card">
            <div className="s3-modal-header">
              <div className="modal-title-wrap">
                <ShieldCheck size={22} className="text-emerald" />
                <div>
                  <h3>Security Posture: {inspectModal.bucket.bucket_name}</h3>
                  <span className="modal-sub-region">Region: {inspectModal.bucket.region}</span>
                </div>
              </div>
              <button
                type="button"
                className="modal-close-btn"
                onClick={() => setInspectModal({ isOpen: false, bucket: null })}
                aria-label="Close dialog"
              >
                <X size={18} />
              </button>
            </div>

            <div className="s3-modal-body">
              {/* BPA Settings Grid */}
              <div className="posture-section">
                <h4 className="section-title">
                  <Lock size={16} /> Block Public Access (BPA)
                </h4>
                <div className="posture-grid">
                  <div className="posture-item">
                    <span className="item-label">Block Public ACLs</span>
                    <span className="item-val">
                      {inspectModal.bucket.block_public_access?.BlockPublicAcls ? (
                        <CheckCircle2 size={16} className="text-emerald" />
                      ) : (
                        <AlertTriangle size={16} className="text-amber" />
                      )}
                      {inspectModal.bucket.block_public_access?.BlockPublicAcls ? "Enabled" : "Disabled"}
                    </span>
                  </div>
                  <div className="posture-item">
                    <span className="item-label">Ignore Public ACLs</span>
                    <span className="item-val">
                      {inspectModal.bucket.block_public_access?.IgnorePublicAcls ? (
                        <CheckCircle2 size={16} className="text-emerald" />
                      ) : (
                        <AlertTriangle size={16} className="text-amber" />
                      )}
                      {inspectModal.bucket.block_public_access?.IgnorePublicAcls ? "Enabled" : "Disabled"}
                    </span>
                  </div>
                  <div className="posture-item">
                    <span className="item-label">Block Public Policy</span>
                    <span className="item-val">
                      {inspectModal.bucket.block_public_access?.BlockPublicPolicy ? (
                        <CheckCircle2 size={16} className="text-emerald" />
                      ) : (
                        <AlertTriangle size={16} className="text-amber" />
                      )}
                      {inspectModal.bucket.block_public_access?.BlockPublicPolicy ? "Enabled" : "Disabled"}
                    </span>
                  </div>
                  <div className="posture-item">
                    <span className="item-label">Restrict Public Buckets</span>
                    <span className="item-val">
                      {inspectModal.bucket.block_public_access?.RestrictPublicBuckets ? (
                        <CheckCircle2 size={16} className="text-emerald" />
                      ) : (
                        <AlertTriangle size={16} className="text-amber" />
                      )}
                      {inspectModal.bucket.block_public_access?.RestrictPublicBuckets ? "Enabled" : "Disabled"}
                    </span>
                  </div>
                </div>
              </div>

              {/* Encryption & Policy Settings Grid */}
              <div className="posture-section">
                <h4 className="section-title">
                  <Key size={16} /> Encryption & Access Policy
                </h4>
                <div className="posture-grid">
                  <div className="posture-item">
                    <span className="item-label">Default Encryption (SSE)</span>
                    <span className="item-val">
                      {inspectModal.bucket.encryption?.enabled ? (
                        <span className="text-emerald font-semibold">
                          Enabled ({inspectModal.bucket.encryption?.algorithm || "AES256"})
                        </span>
                      ) : (
                        <span className="text-amber font-semibold">Disabled / Not Configured</span>
                      )}
                    </span>
                  </div>
                  <div className="posture-item">
                    <span className="item-label">Bucket Policy Status</span>
                    <span className="item-val">
                      {inspectModal.bucket.bucket_policy?.is_public ? (
                        <span className="text-rose font-semibold">PUBLIC EXPOSURE</span>
                      ) : inspectModal.bucket.bucket_policy?.exists ? (
                        <span className="text-emerald font-semibold">Restricted</span>
                      ) : (
                        <span className="text-slate-400">No Custom Policy</span>
                      )}
                    </span>
                  </div>
                  <div className="posture-item">
                    <span className="item-label">Bucket ACL Status</span>
                    <span className="item-val">
                      {inspectModal.bucket.acl?.public ? (
                        <span className="text-rose font-semibold">Public Grants Found</span>
                      ) : (
                        <span className="text-emerald font-semibold">Private (No Public Grants)</span>
                      )}
                    </span>
                  </div>
                  <div className="posture-item">
                    <span className="item-label">Bucket Versioning</span>
                    <span className="item-val">
                      {inspectModal.bucket.versioning?.enabled ? (
                        <span className="text-emerald font-semibold">Enabled</span>
                      ) : (
                        <span className="text-slate-400">{inspectModal.bucket.versioning?.status || "Disabled"}</span>
                      )}
                    </span>
                  </div>
                </div>
              </div>
            </div>

            <div className="s3-modal-footer">
              <button
                type="button"
                className="modal-btn-cancel"
                onClick={() => setInspectModal({ isOpen: false, bucket: null })}
              >
                Close
              </button>
            </div>
          </div>
        </div>
      )}

      {/* Explicit Confirmation Dialog Modal */}
      {actionModal.isOpen && actionModal.bucket && (
        <div className="s3-modal-overlay" role="dialog" aria-modal="true">
          <div className="s3-modal-card">
            <div className="s3-modal-header">
              <div className="modal-title-wrap">
                <AlertTriangle size={20} className="text-amber" />
                <h3>Confirm S3 Security Remediation</h3>
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

            <div className="s3-modal-body">
              <p className="modal-description">
                You are about to execute an audited security remediation: <strong>{actionModal.actionLabel}</strong>.
              </p>

              <div className="modal-context-box">
                <div className="context-row">
                  <span className="context-label">Bucket Name:</span>
                  <span className="context-value mono">{actionModal.bucket.bucket_name}</span>
                </div>
                <div className="context-row">
                  <span className="context-label">AWS Account:</span>
                  <span className="context-value">
                    {currentAccount?.account_name || selectedAccountId} (
                    {currentAccount?.aws_account_id || currentAccount?.account || "-"})
                  </span>
                </div>
                <div className="context-row">
                  <span className="context-label">Bucket Region:</span>
                  <span className="context-value mono">{actionModal.bucket.region}</span>
                </div>
                <div className="context-row">
                  <span className="context-label">Proposed Change:</span>
                  <span className="context-value">{actionModal.actionLabel}</span>
                </div>
              </div>

              <div className="modal-safety-notice">
                <Shield size={16} />
                <span>
                  This action requires Owner/Admin permissions. It will be recorded in the CloudGuardAI tamper-evident audit log and immediately verified via post-state inspection.
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
                  I confirm that I want to apply <strong>{actionModal.actionLabel}</strong> to bucket{" "}
                  <code>{actionModal.bucket.bucket_name}</code> in <code>{actionModal.bucket.region}</code>.
                </label>
              </div>
            </div>

            <div className="s3-modal-footer">
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
                className="modal-btn-execute btn-modal-remediate"
                onClick={handleExecuteAction}
                disabled={!actionConfirmed || actionExecuting}
              >
                {actionExecuting ? (
                  <>
                    <RefreshCw size={14} className="spin" />
                    <span>Executing Control...</span>
                  </>
                ) : (
                  <span>Execute Remediation</span>
                )}
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
