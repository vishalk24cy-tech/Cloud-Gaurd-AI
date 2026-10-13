import { useCallback, useEffect, useId, useMemo, useRef, useState } from "react";
import { Link } from "react-router-dom";
import {
  Server,
  RefreshCw,
  Search,
  AlertTriangle,
  ChevronLeft,
  ChevronRight,
  Shield,
  Activity,
  CheckCircle2,
  AlertCircle,
  HelpCircle,
  Clock,
  Layers,
  Network,
  Play,
  Square,
  RotateCw,
  X,
  Lock,
} from "lucide-react";
import {
  getAWSAccounts,
  getEC2Instances,
  controlEC2Instance,
} from "../services/awsService";
import "./EC2Instances.css";

const STANDARD_AWS_REGIONS = [
  { id: "ap-south-1", name: "Asia Pacific (Mumbai) - ap-south-1" },
  { id: "us-east-1", name: "US East (N. Virginia) - us-east-1" },
  { id: "us-east-2", name: "US East (Ohio) - us-east-2" },
  { id: "us-west-1", name: "US West (N. California) - us-west-1" },
  { id: "us-west-2", name: "US West (Oregon) - us-west-2" },
  { id: "eu-west-1", name: "Europe (Ireland) - eu-west-1" },
  { id: "eu-central-1", name: "Europe (Frankfurt) - eu-central-1" },
  { id: "ap-southeast-1", name: "Asia Pacific (Singapore) - ap-southeast-1" },
  { id: "ap-northeast-1", name: "Asia Pacific (Tokyo) - ap-northeast-1" },
  { id: "sa-east-1", name: "South America (São Paulo) - sa-east-1" },
];

export default function EC2Instances() {
  const accountSelectId = useId();
  const regionSelectId = useId();
  const searchInputId = useId();
  const stateFilterId = useId();
  const confirmCheckId = useId();

  // Accounts state
  const [accounts, setAccounts] = useState([]);
  const [accountsLoading, setAccountsLoading] = useState(true);
  const [selectedAccountId, setSelectedAccountId] = useState("");

  // Inventory state
  const [selectedRegion, setSelectedRegion] = useState("us-east-1");
  const [instances, setInstances] = useState([]);
  const [totalCount, setTotalCount] = useState(0);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState(null);
  const [regionalScopeNotice, setRegionalScopeNotice] = useState("");
  const [lastRefreshed, setLastRefreshed] = useState(null);

  // Pagination state
  const [nextToken, setNextToken] = useState(null);
  const [previousTokens, setPreviousTokens] = useState([]);
  const [currentToken, setCurrentToken] = useState(null);
  const [pageSize, setPageSize] = useState(20);

  // Search & filter
  const [searchTerm, setSearchTerm] = useState("");
  const [stateFilter, setStateFilter] = useState("all");

  // Action / Mutation Modal state
  const [actionModal, setActionModal] = useState({
    isOpen: false,
    instance: null,
    action: null, // "start" | "stop" | "reboot"
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
          setSelectedRegion(first.region || "ap-south-1");
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

  // Currently selected account metadata
  const currentAccount = useMemo(() => {
    return (
      accounts.find(
        (a) =>
          String(a._id) === String(selectedAccountId) ||
          String(a.aws_account_id) === String(selectedAccountId) ||
          String(a.account) === String(selectedAccountId)
      ) || null
    );
  }, [accounts, selectedAccountId]);

  // ============================================================
  // FETCH EC2 INVENTORY (RACE-CONDITION SAFE)
  // ============================================================
  const fetchInventory = useCallback(
    async (targetToken = null) => {
      if (!selectedAccountId) return;

      const requestId = ++latestRequestIdRef.current;
      setLoading(true);
      setError(null);

      try {
        const params = {
          region: selectedRegion,
          max_results: pageSize,
        };
        if (targetToken) {
          params.next_token = targetToken;
        }

        const data = await getEC2Instances(selectedAccountId, params);

        if (requestId !== latestRequestIdRef.current) {
          return;
        }

        setInstances(Array.isArray(data.instances) ? data.instances : []);
        setTotalCount(data.total_count ?? (data.instances?.length || 0));
        setNextToken(data.next_token || null);
        setRegionalScopeNotice(data.regional_scope || "");
        setLastRefreshed(new Date());
      } catch (err) {
        if (requestId !== latestRequestIdRef.current) {
          return;
        }

        const status = err?.response?.status;
        const detail = err?.response?.data?.detail;

        if (status === 403) {
          setError(
            detail ||
              "AWS Access Denied: The IAM role lacks ec2:DescribeInstances permission for this region."
          );
        } else if (status === 404) {
          setError(
            "Connected AWS Account not found or belongs to another organization."
          );
        } else if (status === 429) {
          setError(
            "AWS API rate limit exceeded. Please wait a moment and try refreshing."
          );
        } else {
          setError(
            detail ||
              err?.message ||
              "Failed to communicate with AWS EC2 service. Verify network connectivity."
          );
        }
        setInstances([]);
        setTotalCount(0);
        setNextToken(null);
      } finally {
        if (requestId === latestRequestIdRef.current) {
          setLoading(false);
        }
      }
    },
    [selectedAccountId, selectedRegion, pageSize]
  );

  // Trigger fetch when account, region, or page size changes
  useEffect(() => {
    if (!selectedAccountId) return;
    setCurrentToken(null);
    setPreviousTokens([]);
    fetchInventory(null);
  }, [selectedAccountId, selectedRegion, pageSize, fetchInventory]);

  // Handle Account Change
  const handleAccountChange = (e) => {
    const newId = e.target.value;
    setSelectedAccountId(newId);
    const targetAcc = accounts.find(
      (a) =>
        String(a._id) === String(newId) ||
        String(a.aws_account_id) === String(newId) ||
        String(a.account) === String(newId)
    );
    if (targetAcc?.region) {
      setSelectedRegion(targetAcc.region);
    }
  };

  // Pagination Handlers
  const handleNextPage = () => {
    if (!nextToken) return;
    setPreviousTokens((prev) => [...prev, currentToken]);
    setCurrentToken(nextToken);
    fetchInventory(nextToken);
  };

  const handlePrevPage = () => {
    if (previousTokens.length === 0) return;
    const newPrevTokens = [...previousTokens];
    const prevT = newPrevTokens.pop();
    setPreviousTokens(newPrevTokens);
    setCurrentToken(prevT);
    fetchInventory(prevT);
  };

  // ============================================================
  // ACTION MODAL & EXECUTION (PHASE 2C)
  // ============================================================
  const openActionModal = (instance, action) => {
    setActionModal({
      isOpen: true,
      instance,
      action,
    });
    setActionConfirmed(false);
  };

  const closeActionModal = () => {
    if (actionExecuting) return;
    setActionModal({
      isOpen: false,
      instance: null,
      action: null,
    });
    setActionConfirmed(false);
  };

  const handleExecuteAction = async () => {
    if (!actionModal.instance || !actionModal.action || !actionConfirmed) return;

    setActionExecuting(true);
    setActionFeedback(null);

    const inst = actionModal.instance;
    const action = actionModal.action;
    const region = inst.region || selectedRegion;

    try {
      const res = await controlEC2Instance(selectedAccountId, inst.instance_id, {
        action,
        region,
        confirmed: true,
      });

      setActionFeedback({
        type: "success",
        message:
          res.message ||
          `Successfully initiated ${action.toUpperCase()} on instance ${inst.instance_id}.`,
      });

      closeActionModal();

      // Refresh inventory to display updated state
      fetchInventory(currentToken);
    } catch (err) {
      const detail =
        err?.response?.data?.detail ||
        err?.message ||
        `Failed to execute ${action} on instance ${inst.instance_id}.`;

      setActionFeedback({
        type: "error",
        message: detail,
      });
    } finally {
      setActionExecuting(false);
    }
  };

  // Local Filtered Instances
  const filteredInstances = useMemo(() => {
    return instances.filter((inst) => {
      const name = (inst.name || "").toLowerCase();
      const id = (inst.instance_id || "").toLowerCase();
      const privateIp = (inst.private_ip || "").toLowerCase();
      const publicIp = (inst.public_ip || "").toLowerCase();
      const type = (inst.instance_type || "").toLowerCase();
      const search = searchTerm.trim().toLowerCase();

      const matchesSearch =
        !search ||
        name.includes(search) ||
        id.includes(search) ||
        privateIp.includes(search) ||
        publicIp.includes(search) ||
        type.includes(search);

      const matchesState =
        stateFilter === "all" ||
        (inst.state || "").toLowerCase() === stateFilter.toLowerCase();

      return matchesSearch && matchesState;
    });
  }, [instances, searchTerm, stateFilter]);

  // Stats calculation
  const stats = useMemo(() => {
    let running = 0;
    let stopped = 0;
    let other = 0;

    instances.forEach((inst) => {
      const s = (inst.state || "").toLowerCase();
      if (s === "running") running++;
      else if (s === "stopped") stopped++;
      else other++;
    });

    return {
      total: instances.length,
      running,
      stopped,
      other,
    };
  }, [instances]);

  // State Badge Helper
  const renderStateBadge = (state) => {
    const s = (state || "unknown").toLowerCase();
    let badgeClass = "badge-neutral";
    let icon = <HelpCircle size={13} />;

    if (s === "running") {
      badgeClass = "badge-running";
      icon = <CheckCircle2 size={13} />;
    } else if (s === "stopped") {
      badgeClass = "badge-stopped";
      icon = <AlertCircle size={13} />;
    } else if (s === "pending" || s === "stopping") {
      badgeClass = "badge-transitional";
      icon = <Clock size={13} />;
    } else if (s === "terminated") {
      badgeClass = "badge-terminated";
      icon = <AlertTriangle size={13} />;
    }

    return (
      <span className={`ec2-state-badge ${badgeClass}`}>
        {icon}
        <span>{s.toUpperCase()}</span>
      </span>
    );
  };

  // ============================================================
  // RENDER UI
  // ============================================================
  return (
    <div className="ec2-inventory-page" role="main">
      {/* Page Header */}
      <header className="ec2-header">
        <div className="ec2-header-left">
          <div className="ec2-kicker">
            <Shield size={12} />
            <span>AWS CLOUD INFRASTRUCTURE MANAGEMENT</span>
          </div>
          <h1>EC2 Instances & Resource Controls</h1>
          <p>
            Secure, audited resource management with real-time posture
            inspection, Start, Stop, and Reboot controls for connected AWS accounts.
          </p>
        </div>

        <div className="ec2-header-actions">
          <div className="read-only-pill" title="Owner/Admin authorization enforced for mutations">
            <Lock size={12} />
            <span>Secure Role-Gated Controls</span>
          </div>

          <button
            type="button"
            className="ec2-refresh-btn"
            onClick={() => fetchInventory(currentToken)}
            disabled={loading || accountsLoading || !selectedAccountId}
            aria-label="Refresh EC2 Inventory"
          >
            <RefreshCw size={15} className={loading ? "spin" : ""} />
            <span>{loading ? "Refreshing..." : "Refresh"}</span>
          </button>
        </div>
      </header>

      {/* Account & Region Selector Bar */}
      <section className="ec2-controls-card" aria-label="Inventory Controls">
        <div className="ec2-control-group">
          <label htmlFor={accountSelectId} className="control-label">
            Connected AWS Account
          </label>
          <div className="select-wrapper">
            <select
              id={accountSelectId}
              value={selectedAccountId}
              onChange={handleAccountChange}
              disabled={accountsLoading || accounts.length === 0}
              className="ec2-select"
            >
              {accounts.length === 0 && (
                <option value="">No connected accounts found</option>
              )}
              {accounts.map((acc) => {
                const id = acc._id || acc.aws_account_id || acc.account;
                const name =
                  acc.account_name || acc.account || "AWS Account";
                const num = acc.aws_account_id || acc.account || "";
                return (
                  <option key={id} value={id}>
                    {name} {num ? `(${num})` : ""}
                  </option>
                );
              })}
            </select>
          </div>
        </div>

        <div className="ec2-control-group">
          <label htmlFor={regionSelectId} className="control-label">
            AWS Region
          </label>
          <div className="select-wrapper">
            <select
              id={regionSelectId}
              value={selectedRegion}
              onChange={(e) => setSelectedRegion(e.target.value)}
              disabled={loading || !selectedAccountId}
              className="ec2-select"
            >
              {STANDARD_AWS_REGIONS.map((r) => (
                <option key={r.id} value={r.id}>
                  {r.name}
                </option>
              ))}
            </select>
          </div>
        </div>

        <div className="ec2-control-group search-group">
          <label htmlFor={searchInputId} className="control-label">
            Filter Instances
          </label>
          <div className="ec2-search-input-wrap">
            <Search size={14} className="search-icon" />
            <input
              id={searchInputId}
              type="text"
              placeholder="Search by name, instance ID, IP..."
              value={searchTerm}
              onChange={(e) => setSearchTerm(e.target.value)}
              className="ec2-input"
            />
          </div>
        </div>

        <div className="ec2-control-group state-group">
          <label htmlFor={stateFilterId} className="control-label">
            State
          </label>
          <div className="select-wrapper">
            <select
              id={stateFilterId}
              value={stateFilter}
              onChange={(e) => setStateFilter(e.target.value)}
              className="ec2-select"
            >
              <option value="all">All States</option>
              <option value="running">Running</option>
              <option value="stopped">Stopped</option>
              <option value="pending">Pending</option>
              <option value="stopping">Stopping</option>
              <option value="terminated">Terminated</option>
            </select>
          </div>
        </div>
      </section>

      {/* Scope Notice Banner */}
      {regionalScopeNotice && !error && (
        <div className="ec2-scope-banner" role="note">
          <Layers size={15} />
          <span>{regionalScopeNotice}</span>
          {lastRefreshed && (
            <span className="last-refreshed">
              • Updated: {lastRefreshed.toLocaleTimeString()}
            </span>
          )}
        </div>
      )}

      {/* Action Execution Feedback Alert */}
      {actionFeedback && (
        <div
          className={`ec2-feedback-banner ${
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
        <div className="ec2-error-banner" role="alert">
          <div className="error-icon-box">
            <AlertTriangle size={18} />
          </div>
          <div className="error-content">
            <h4>Failed to Load EC2 Inventory</h4>
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
      <section className="ec2-stats-grid" aria-label="Instance Statistics">
        <div className="ec2-stat-card total">
          <div className="stat-icon-wrapper">
            <Server size={20} />
          </div>
          <div className="stat-info">
            <span className="stat-label">Total Discovered</span>
            <span className="stat-value">{totalCount}</span>
          </div>
        </div>

        <div className="ec2-stat-card running">
          <div className="stat-icon-wrapper">
            <Activity size={20} />
          </div>
          <div className="stat-info">
            <span className="stat-label">Running Instances</span>
            <span className="stat-value">{stats.running}</span>
          </div>
        </div>

        <div className="ec2-stat-card stopped">
          <div className="stat-icon-wrapper">
            <AlertCircle size={20} />
          </div>
          <div className="stat-info">
            <span className="stat-label">Stopped</span>
            <span className="stat-value">{stats.stopped}</span>
          </div>
        </div>

        <div className="ec2-stat-card region">
          <div className="stat-icon-wrapper">
            <Network size={20} />
          </div>
          <div className="stat-info">
            <span className="stat-label">Active Region</span>
            <span className="stat-value text-region">{selectedRegion}</span>
          </div>
        </div>
      </section>

      {/* Main Table / Content Section */}
      <section className="ec2-table-card" aria-label="EC2 Instance List">
        {loading ? (
          <div className="ec2-loading-state" role="status">
            <RefreshCw size={28} className="spin" />
            <p>Querying AWS EC2 DescribeInstances in {selectedRegion}...</p>
            <span className="loading-sub">
              Fetching authorized instance details via STS assumed role
            </span>
          </div>
        ) : accounts.length === 0 && !accountsLoading ? (
          <div className="ec2-empty-state">
            <Server size={42} className="empty-icon" />
            <h3>No Connected AWS Accounts</h3>
            <p>
              Connect an AWS IAM Role first to view real-time resource inventory
              and execute authorized controls.
            </p>
            <Link to="/connect-aws" className="ec2-cta-btn">
              Connect AWS Account
            </Link>
          </div>
        ) : filteredInstances.length === 0 ? (
          <div className="ec2-empty-state">
            <Server size={42} className="empty-icon" />
            <h3>No EC2 Instances Found</h3>
            <p>
              {searchTerm || stateFilter !== "all"
                ? "No instances match your search or state filter."
                : `No EC2 instances exist in account "${
                    currentAccount?.account_name || selectedAccountId
                  }" within region "${selectedRegion}".`}
            </p>
            {(searchTerm || stateFilter !== "all") && (
              <button
                type="button"
                className="reset-filters-btn"
                onClick={() => {
                  setSearchTerm("");
                  setStateFilter("all");
                }}
              >
                Clear Filters
              </button>
            )}
          </div>
        ) : (
          <div className="table-responsive">
            <table className="ec2-table">
              <thead>
                <tr>
                  <th>Instance Name & ID</th>
                  <th>State</th>
                  <th>Type</th>
                  <th>Region / AZ</th>
                  <th>Private IP</th>
                  <th>Public IP</th>
                  <th>VPC & Subnet</th>
                  <th>Launch Time</th>
                  <th className="th-actions">Actions</th>
                </tr>
              </thead>
              <tbody>
                {filteredInstances.map((inst) => {
                  const hasName = Boolean(inst.name);
                  const state = (inst.state || "").toLowerCase();
                  const isRunning = state === "running";
                  const isStopped = state === "stopped";
                  const isTransitional = state === "pending" || state === "stopping";

                  return (
                    <tr key={inst.instance_id}>
                      <td className="cell-instance-identity">
                        <div className="identity-wrap">
                          <span
                            className={
                              hasName ? "instance-name" : "instance-name-missing"
                            }
                            title={hasName ? inst.name : "No Name tag assigned"}
                          >
                            {hasName ? inst.name : "unnamed-instance"}
                          </span>
                          <span className="instance-id-badge" title="AWS Instance ID">
                            {inst.instance_id}
                          </span>
                        </div>
                      </td>

                      <td className="cell-state">
                        {renderStateBadge(inst.state)}
                      </td>

                      <td className="cell-type">
                        <span className="type-badge">{inst.instance_type}</span>
                      </td>

                      <td className="cell-location">
                        <div className="location-wrap">
                          <span className="region-name">{inst.region}</span>
                          <span className="az-tag">
                            {inst.availability_zone || "-"}
                          </span>
                        </div>
                      </td>

                      <td className="cell-ip">
                        <code>{inst.private_ip || "-"}</code>
                      </td>

                      <td className="cell-ip">
                        {inst.public_ip ? (
                          <code className="public-ip-code">{inst.public_ip}</code>
                        ) : (
                          <span className="none-muted">None</span>
                        )}
                      </td>

                      <td className="cell-network">
                        <div className="network-wrap">
                          <span className="network-id" title="VPC ID">
                            {inst.vpc_id || "-"}
                          </span>
                          <span className="subnet-id" title="Subnet ID">
                            {inst.subnet_id || "-"}
                          </span>
                        </div>
                      </td>

                      <td className="cell-time">
                        <span className="time-text">
                          {inst.launch_time
                            ? new Date(inst.launch_time).toLocaleDateString(
                                undefined,
                                {
                                  month: "short",
                                  day: "numeric",
                                  year: "numeric",
                                  hour: "2-digit",
                                  minute: "2-digit",
                                }
                              )
                            : "-"}
                        </span>
                      </td>

                      {/* Mutation Control Actions */}
                      <td className="cell-actions">
                        <div className="instance-actions-btn-group">
                          {isStopped && (
                            <button
                              type="button"
                              className="action-btn btn-start"
                              onClick={() => openActionModal(inst, "start")}
                              title="Start EC2 Instance"
                              aria-label={`Start instance ${inst.instance_id}`}
                            >
                              <Play size={13} />
                              <span>Start</span>
                            </button>
                          )}

                          {isRunning && (
                            <>
                              <button
                                type="button"
                                className="action-btn btn-stop"
                                onClick={() => openActionModal(inst, "stop")}
                                title="Stop EC2 Instance"
                                aria-label={`Stop instance ${inst.instance_id}`}
                              >
                                <Square size={13} />
                                <span>Stop</span>
                              </button>
                              <button
                                type="button"
                                className="action-btn btn-reboot"
                                onClick={() => openActionModal(inst, "reboot")}
                                title="Reboot EC2 Instance"
                                aria-label={`Reboot instance ${inst.instance_id}`}
                              >
                                <RotateCw size={13} />
                                <span>Reboot</span>
                              </button>
                            </>
                          )}

                          {isTransitional && (
                            <span className="action-disabled-tag">
                              In Transition...
                            </span>
                          )}

                          {!isRunning && !isStopped && !isTransitional && (
                            <span className="action-disabled-tag">N/A</span>
                          )}
                        </div>
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        )}

        {/* Pagination Footer */}
        <div className="ec2-pagination-bar">
          <div className="pagination-info">
            <span>
              Showing <strong>{filteredInstances.length}</strong> of{" "}
              <strong>{totalCount}</strong> instances
            </span>
          </div>

          <div className="pagination-controls">
            <div className="page-size-selector">
              <label htmlFor="ec2-page-size-select">Per page:</label>
              <select
                id="ec2-page-size-select"
                value={pageSize}
                onChange={(e) => setPageSize(Number(e.target.value))}
                className="page-size-dropdown"
                disabled={loading}
              >
                <option value={10}>10</option>
                <option value={20}>20</option>
                <option value={50}>50</option>
                <option value={100}>100</option>
              </select>
            </div>

            <button
              type="button"
              className="page-nav-btn"
              onClick={handlePrevPage}
              disabled={previousTokens.length === 0 || loading}
              aria-label="Previous Page"
            >
              <ChevronLeft size={16} />
              <span>Previous</span>
            </button>

            <button
              type="button"
              className="page-nav-btn"
              onClick={handleNextPage}
              disabled={!nextToken || loading}
              aria-label="Next Page"
            >
              <span>Next</span>
              <ChevronRight size={16} />
            </button>
          </div>
        </div>
      </section>

      {/* Explicit Confirmation Dialog Modal */}
      {actionModal.isOpen && actionModal.instance && (
        <div className="ec2-modal-overlay" role="dialog" aria-modal="true">
          <div className="ec2-modal-card">
            <div className="ec2-modal-header">
              <div className="modal-title-wrap">
                <AlertTriangle
                  size={20}
                  className={
                    actionModal.action === "stop"
                      ? "text-amber"
                      : actionModal.action === "start"
                      ? "text-emerald"
                      : "text-sky"
                  }
                />
                <h3>Confirm EC2 {actionModal.action?.toUpperCase()} Action</h3>
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

            <div className="ec2-modal-body">
              <p className="modal-description">
                You are about to execute an audited <strong>{actionModal.action?.toUpperCase()}</strong> action on the target AWS resource.
              </p>

              <div className="modal-context-box">
                <div className="context-row">
                  <span className="context-label">Instance Name:</span>
                  <span className="context-value">
                    {actionModal.instance.name || "unnamed-instance"}
                  </span>
                </div>
                <div className="context-row">
                  <span className="context-label">Instance ID:</span>
                  <span className="context-value mono">
                    {actionModal.instance.instance_id}
                  </span>
                </div>
                <div className="context-row">
                  <span className="context-label">AWS Account:</span>
                  <span className="context-value">
                    {currentAccount?.account_name || selectedAccountId} (
                    {currentAccount?.aws_account_id || currentAccount?.account || "-"}
                    )
                  </span>
                </div>
                <div className="context-row">
                  <span className="context-label">Region:</span>
                  <span className="context-value mono">
                    {actionModal.instance.region || selectedRegion}
                  </span>
                </div>
                <div className="context-row">
                  <span className="context-label">Current State:</span>
                  <span className="context-value">
                    {renderStateBadge(actionModal.instance.state)}
                  </span>
                </div>
              </div>

              <div className="modal-safety-notice">
                <Shield size={16} />
                <span>
                  This action requires Owner/Admin permissions and will be recorded in the tamper-evident audit log with actor identity and outcome verification.
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
                  I confirm that I want to <strong>{actionModal.action}</strong> instance{" "}
                  <code>{actionModal.instance.instance_id}</code> in{" "}
                  <code>{actionModal.instance.region || selectedRegion}</code>.
                </label>
              </div>
            </div>

            <div className="ec2-modal-footer">
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
                    : "btn-modal-reboot"
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
                  <span>
                    Execute {actionModal.action?.toUpperCase()}
                  </span>
                )}
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
