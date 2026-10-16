import { useCallback, useEffect, useId, useMemo, useRef, useState } from "react";
import { Link } from "react-router-dom";
import {
  Network,
  RefreshCw,
  Search,
  AlertTriangle,
  ChevronLeft,
  ChevronRight,
  Shield,
  ShieldAlert,
  ShieldCheck,
  CheckCircle2,
  AlertCircle,
  Activity,
  Server,
  Layers,
  Globe,
  Radio,
  Lock,
  Unlock,
  Eye,
  Info,
  ExternalLink,
  Trash2,
  ArrowUpRight,
  ArrowDownLeft,
  Filter,
  X,
} from "lucide-react";
import {
  getAWSAccounts,
  getVPCs,
  getSubnets,
  getSecurityGroups,
  getRouteTables,
  getGateways,
  getVPCEndpoints,
  controlSecurityGroup,
} from "../services/awsService";
import "./NetworkResources.css";

const STANDARD_AWS_REGIONS = [
  { id: "all", name: "All Regions (Multi-Region Discovery)" },
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

export default function NetworkResources() {
  const accountSelectId = useId();
  const regionSelectId = useId();
  const searchInputId = useId();
  const postureFilterId = useId();

  // Accounts state
  const [accounts, setAccounts] = useState([]);
  const [accountsLoading, setAccountsLoading] = useState(true);
  const [selectedAccountId, setSelectedAccountId] = useState("");

  // Global region & tab state
  const [selectedRegion, setSelectedRegion] = useState("us-east-1");
  const [activeTab, setActiveTab] = useState("security-groups"); // "security-groups" | "vpcs" | "subnets" | "route-tables" | "gateways" | "endpoints"
  const [searchTerm, setSearchTerm] = useState("");
  const [postureFilter, setPostureFilter] = useState("all");
  const [lastRefreshed, setLastRefreshed] = useState(null);

  // Tab Data States
  const [vpcs, setVpcs] = useState([]);
  const [subnets, setSubnets] = useState([]);
  const [securityGroups, setSecurityGroups] = useState([]);
  const [routeTables, setRouteTables] = useState([]);
  const [gateways, setGateways] = useState([]);
  const [endpoints, setEndpoints] = useState([]);

  // Summaries
  const [sgSummary, setSgSummary] = useState(null);
  const [vpcSummary, setVpcSummary] = useState(null);
  const [subnetSummary, setSubnetSummary] = useState(null);
  const [rtSummary, setRtSummary] = useState(null);
  const [gwSummary, setGwSummary] = useState(null);
  const [epSummary, setEpSummary] = useState(null);

  // Loading & Error States
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState(null);
  const [coverage, setCoverage] = useState("COMPLETE");
  const [regionalFailures, setRegionalFailures] = useState([]);

  // Inspector Modal state
  const [inspectModal, setInspectModal] = useState({
    isOpen: false,
    group: null,
  });

  // Action / Remediation Modal state
  const [actionModal, setActionModal] = useState({
    isOpen: false,
    group: null,
    action: null, // "revoke_ssh_ingress" | "revoke_rdp_ingress" | "revoke_all_traffic_ingress" | "revoke_ingress_rule"
    actionLabel: "",
    ruleSpec: null,
    riskDescription: "",
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
  // FETCH INVENTORY DATA FOR ACTIVE TAB
  // ============================================================
  const fetchNetworkData = useCallback(
    async (tabToFetch = activeTab) => {
      if (!selectedAccountId) return;

      const requestId = ++latestRequestIdRef.current;
      setLoading(true);
      setError(null);

      try {
        const baseParams = {
          region: selectedRegion,
          search: searchTerm ? searchTerm.trim() : undefined,
        };

        if (tabToFetch === "security-groups") {
          const sgRes = await getSecurityGroups(selectedAccountId, {
            ...baseParams,
            posture: postureFilter !== "all" ? postureFilter : undefined,
          });
          if (requestId !== latestRequestIdRef.current) return;
          setSecurityGroups(sgRes.security_groups || []);
          setSgSummary(sgRes.summary || null);
          setCoverage(sgRes.coverage || "COMPLETE");
          setRegionalFailures(sgRes.regional_failures || []);
        } else if (tabToFetch === "vpcs") {
          const vpcRes = await getVPCs(selectedAccountId, baseParams);
          if (requestId !== latestRequestIdRef.current) return;
          setVpcs(vpcRes.vpcs || []);
          setVpcSummary(vpcRes.summary || null);
          setCoverage(vpcRes.coverage || "COMPLETE");
          setRegionalFailures(vpcRes.regional_failures || []);
        } else if (tabToFetch === "subnets") {
          const subRes = await getSubnets(selectedAccountId, baseParams);
          if (requestId !== latestRequestIdRef.current) return;
          setSubnets(subRes.subnets || []);
          setSubnetSummary(subRes.summary || null);
          setCoverage(subRes.coverage || "COMPLETE");
          setRegionalFailures(subRes.regional_failures || []);
        } else if (tabToFetch === "route-tables") {
          const rtRes = await getRouteTables(selectedAccountId, baseParams);
          if (requestId !== latestRequestIdRef.current) return;
          setRouteTables(rtRes.route_tables || []);
          setRtSummary(rtRes.summary || null);
          setCoverage(rtRes.coverage || "COMPLETE");
          setRegionalFailures(rtRes.regional_failures || []);
        } else if (tabToFetch === "gateways") {
          const gwRes = await getGateways(selectedAccountId, baseParams);
          if (requestId !== latestRequestIdRef.current) return;
          setGateways(gwRes.gateways || []);
          setGwSummary(gwRes.summary || null);
          setCoverage(gwRes.coverage || "COMPLETE");
          setRegionalFailures(gwRes.regional_failures || []);
        } else if (tabToFetch === "endpoints") {
          const epRes = await getVPCEndpoints(selectedAccountId, baseParams);
          if (requestId !== latestRequestIdRef.current) return;
          setEndpoints(epRes.endpoints || []);
          setEpSummary(epRes.summary || null);
          setCoverage(epRes.coverage || "COMPLETE");
          setRegionalFailures(epRes.regional_failures || []);
        }

        setLastRefreshed(new Date());
      } catch (err) {
        if (requestId !== latestRequestIdRef.current) return;
        setCoverage("FAILED");
        setRegionalFailures([]);
        setError(
          err?.response?.data?.detail ||
            err?.message ||
            "Failed to fetch network resources from AWS."
        );
      } finally {
        if (requestId === latestRequestIdRef.current) {
          setLoading(false);
        }
      }
    },
    [selectedAccountId, selectedRegion, activeTab, searchTerm, postureFilter]
  );

  useEffect(() => {
    if (selectedAccountId) {
      fetchNetworkData(activeTab);
    }
  }, [selectedAccountId, selectedRegion, activeTab, fetchNetworkData]);

  // Handle Tab Switch
  const handleTabChange = (tabKey) => {
    setActiveTab(tabKey);
    setSearchTerm("");
    setPostureFilter("all");
  };

  // Selected Account helper
  const currentAccount = useMemo(() => {
    return (
      accounts.find(
        (a) => (a._id || a.aws_account_id || a.account) === selectedAccountId
      ) || null
    );
  }, [accounts, selectedAccountId]);

  // ============================================================
  // OPEN REMEDIATION ACTION MODAL
  // ============================================================
  const openActionModal = (group, actionKey, label, ruleSpec = null, riskDesc = "") => {
    setActionModal({
      isOpen: true,
      group,
      action: actionKey,
      actionLabel: label,
      ruleSpec,
      riskDescription: riskDesc,
    });
    setActionConfirmed(false);
    setActionFeedback(null);
  };

  const closeActionModal = () => {
    if (actionExecuting) return;
    setActionModal({
      isOpen: false,
      group: null,
      action: null,
      actionLabel: "",
      ruleSpec: null,
      riskDescription: "",
    });
    setActionConfirmed(false);
    setActionFeedback(null);
  };

  // ============================================================
  // EXECUTE SECURITY GROUP REMEDIATION
  // ============================================================
  const handleExecuteAction = async () => {
    if (!actionModal.group || !actionModal.action || !actionConfirmed) return;

    setActionExecuting(true);
    setActionFeedback(null);

    try {
      const payload = {
        action: actionModal.action,
        region: selectedRegion,
        rule_spec: actionModal.ruleSpec,
        confirmed: true,
      };

      const res = await controlSecurityGroup(
        selectedAccountId,
        actionModal.group.group_id,
        payload
      );

      setActionFeedback({
        type: "success",
        message:
          res.message ||
          `Successfully applied remediation on ${actionModal.group.group_id}.`,
      });

      // Refresh data
      setTimeout(() => {
        fetchNetworkData("security-groups");
        closeActionModal();
      }, 1500);
    } catch (err) {
      setActionFeedback({
        type: "error",
        message:
          err?.response?.data?.detail ||
          err?.message ||
          "Failed to execute remediation action on AWS.",
      });
    } finally {
      setActionExecuting(false);
    }
  };

  // Posture Badge Helper
  const renderPostureBadge = (posture) => {
    switch (posture) {
      case "CRITICAL":
        return (
          <span className="net-badge net-badge-critical">
            <ShieldAlert size={13} /> CRITICAL
          </span>
        );
      case "HIGH_RISK":
        return (
          <span className="net-badge net-badge-high">
            <AlertTriangle size={13} /> HIGH RISK
          </span>
        );
      case "RISK":
        return (
          <span className="net-badge net-badge-risk">
            <AlertCircle size={13} /> RISK
          </span>
        );
      case "SECURE":
        return (
          <span className="net-badge net-badge-secure">
            <ShieldCheck size={13} /> SECURE
          </span>
        );
      case "PUBLIC_ROUTE":
        return (
          <span className="net-badge net-badge-warning">
            <Globe size={13} /> INTERNET ROUTE
          </span>
        );
      case "PRIVATE_ROUTE":
        return (
          <span className="net-badge net-badge-secure">
            <Lock size={13} /> PRIVATE ROUTE
          </span>
        );
      default:
        return (
          <span className="net-badge net-badge-evaluated">
            <Info size={13} /> {posture || "EVALUATED"}
          </span>
        );
    }
  };

  return (
    <div className="net-page-container">
      {/* ======================================================
          HEADER & CONTROLS
          ====================================================== */}
      <header className="net-header">
        <div className="net-header-left">
          <div className="net-icon-wrapper">
            <Network size={28} className="net-header-icon" />
          </div>
          <div>
            <h1 className="net-title">VPC & Network Security</h1>
            <p className="net-subtitle">
              Inventory VPCs, Subnets, Gateways, Route Tables, and inspect Security Group exposure with safe remediation.
            </p>
          </div>
        </div>

        <div className="net-header-controls">
          {/* AWS Account Selector */}
          <div className="net-select-group">
            <label htmlFor={accountSelectId} className="net-select-label">
              AWS Account:
            </label>
            <select
              id={accountSelectId}
              value={selectedAccountId}
              onChange={(e) => setSelectedAccountId(e.target.value)}
              disabled={accountsLoading || accounts.length === 0}
              className="net-select"
            >
              {accounts.length === 0 ? (
                <option value="">No Accounts Connected</option>
              ) : (
                accounts.map((acc) => {
                  const id = acc._id || acc.aws_account_id || acc.account;
                  return (
                    <option key={id} value={id}>
                      {acc.account_name
                        ? `${acc.account_name} (${acc.aws_account_id || acc.account || id})`
                        : acc.aws_account_id || acc.account || id}
                    </option>
                  );
                })
              )}
            </select>
          </div>

          {/* Region Selector */}
          <div className="net-select-group">
            <label htmlFor={regionSelectId} className="net-select-label">
              Region:
            </label>
            <select
              id={regionSelectId}
              value={selectedRegion}
              onChange={(e) => setSelectedRegion(e.target.value)}
              disabled={loading}
              className="net-select"
            >
              {STANDARD_AWS_REGIONS.map((r) => (
                <option key={r.id} value={r.id}>
                  {r.name}
                </option>
              ))}
            </select>
          </div>

          {/* Refresh Button */}
          <button
            type="button"
            onClick={() => fetchNetworkData(activeTab)}
            disabled={loading || !selectedAccountId}
            className="net-btn-secondary"
            title="Refresh network inventory"
          >
            <RefreshCw size={16} className={loading ? "spin" : ""} />
            <span>Refresh</span>
          </button>
        </div>
      </header>

      {/* ======================================================
          SUMMARY METRICS CARDS
          ====================================================== */}
      <section className="net-metrics-grid" aria-label="Network Metrics Overview">
        <div className="net-metric-card">
          <div className="net-metric-header">
            <span className="net-metric-title">Discovered Security Groups</span>
            <Shield size={18} className="text-blue" />
          </div>
          <div className="net-metric-value">{sgSummary?.total_security_groups ?? securityGroups.length}</div>
          <div className="net-metric-footer">
            <span className="text-muted">In {selectedRegion}</span>
          </div>
        </div>

        <div className="net-metric-card">
          <div className="net-metric-header">
            <span className="net-metric-title">Critical & Open SGs</span>
            <ShieldAlert size={18} className="text-red" />
          </div>
          <div className="net-metric-value text-red">
            {(sgSummary?.critical_count || 0) + (sgSummary?.high_risk_count || 0)}
          </div>
          <div className="net-metric-footer">
            <span>{sgSummary?.open_ssh_count || 0} Open SSH</span>
            <span className="dot-sep">•</span>
            <span>{sgSummary?.open_rdp_count || 0} Open RDP</span>
          </div>
        </div>

        <div className="net-metric-card">
          <div className="net-metric-header">
            <span className="net-metric-title">Virtual Private Clouds (VPCs)</span>
            <Layers size={18} className="text-indigo" />
          </div>
          <div className="net-metric-value">{vpcSummary?.total_vpcs ?? vpcs.length}</div>
          <div className="net-metric-footer">
            <span>{vpcSummary?.custom_vpcs ?? 0} Custom</span>
            <span className="dot-sep">•</span>
            <span>{vpcSummary?.default_vpcs ?? 0} Default</span>
          </div>
        </div>

        <div className="net-metric-card">
          <div className="net-metric-header">
            <span className="net-metric-title">Subnets & Gateways</span>
            <Globe size={18} className="text-emerald" />
          </div>
          <div className="net-metric-value">
            {(subnetSummary?.total_subnets ?? subnets.length)}
          </div>
          <div className="net-metric-footer">
            <span>{subnetSummary?.public_subnets ?? 0} Auto-Assign Public IP</span>
          </div>
        </div>
      </section>

      {/* ======================================================
          RESOURCE NAVIGATION TABS
          ====================================================== */}
      <nav className="net-tabs-nav" aria-label="Network Resource Navigation">
        <button
          type="button"
          className={`net-tab-btn ${activeTab === "security-groups" ? "active" : ""}`}
          onClick={() => handleTabChange("security-groups")}
        >
          <Shield size={16} />
          <span>Security Groups</span>
          {sgSummary && (
            <span className="net-tab-counter">{sgSummary.total_security_groups}</span>
          )}
        </button>

        <button
          type="button"
          className={`net-tab-btn ${activeTab === "vpcs" ? "active" : ""}`}
          onClick={() => handleTabChange("vpcs")}
        >
          <Layers size={16} />
          <span>VPCs</span>
          {vpcSummary && (
            <span className="net-tab-counter">{vpcSummary.total_vpcs}</span>
          )}
        </button>

        <button
          type="button"
          className={`net-tab-btn ${activeTab === "subnets" ? "active" : ""}`}
          onClick={() => handleTabChange("subnets")}
        >
          <Server size={16} />
          <span>Subnets</span>
          {subnetSummary && (
            <span className="net-tab-counter">{subnetSummary.total_subnets}</span>
          )}
        </button>

        <button
          type="button"
          className={`net-tab-btn ${activeTab === "route-tables" ? "active" : ""}`}
          onClick={() => handleTabChange("route-tables")}
        >
          <Radio size={16} />
          <span>Route Tables</span>
          {rtSummary && (
            <span className="net-tab-counter">{rtSummary.total_route_tables}</span>
          )}
        </button>

        <button
          type="button"
          className={`net-tab-btn ${activeTab === "gateways" ? "active" : ""}`}
          onClick={() => handleTabChange("gateways")}
        >
          <Globe size={16} />
          <span>Gateways</span>
          {gwSummary && (
            <span className="net-tab-counter">{gwSummary.total_gateways}</span>
          )}
        </button>

        <button
          type="button"
          className={`net-tab-btn ${activeTab === "endpoints" ? "active" : ""}`}
          onClick={() => handleTabChange("endpoints")}
        >
          <ExternalLink size={16} />
          <span>VPC Endpoints</span>
          {epSummary && (
            <span className="net-tab-counter">{epSummary.total_endpoints}</span>
          )}
        </button>
      </nav>

      {/* ======================================================
          TOOLBAR & FILTERS
          ====================================================== */}
      <div className="net-toolbar">
        <div className="net-search-wrapper">
          <Search size={16} className="net-search-icon" />
          <input
            id={searchInputId}
            type="text"
            placeholder={`Search ${activeTab.replace("-", " ")} by name, ID, CIDR...`}
            value={searchTerm}
            onChange={(e) => setSearchTerm(e.target.value)}
            onKeyDown={(e) => e.key === "Enter" && fetchNetworkData(activeTab)}
            className="net-search-input"
          />
          {searchTerm && (
            <button
              type="button"
              onClick={() => {
                setSearchTerm("");
                fetchNetworkData(activeTab);
              }}
              className="net-clear-btn"
            >
              <X size={14} />
            </button>
          )}
        </div>

        {activeTab === "security-groups" && (
          <div className="net-filter-wrapper">
            <Filter size={15} className="text-muted" />
            <select
              id={postureFilterId}
              value={postureFilter}
              onChange={(e) => setPostureFilter(e.target.value)}
              className="net-filter-select"
            >
              <option value="all">All Postures</option>
              <option value="CRITICAL">Critical Exposure</option>
              <option value="HIGH_RISK">High Risk (SSH / RDP)</option>
              <option value="RISK">Medium Risk</option>
              <option value="SECURE">Secure & Scoped</option>
            </select>
          </div>
        )}

        <div className="net-toolbar-meta">
          {lastRefreshed && (
            <span className="net-last-refreshed">
              Refreshed {lastRefreshed.toLocaleTimeString()}
            </span>
          )}
        </div>
      </div>

      {/* Account Disconnected Warning Banner */}
      {currentAccount && currentAccount.status === "disconnected" && (
        <div className="net-error-banner" role="alert" style={{ background: "rgba(239, 68, 68, 0.15)", borderColor: "rgba(239, 68, 68, 0.4)" }}>
          <AlertCircle size={20} className="net-error-icon text-red" />
          <div className="net-error-content">
            <strong>AWS Account Disconnected</strong>
            <p>This AWS account is marked as disconnected. Reconnect or re-verify STS AssumeRole credentials in <Link to="/connect-aws" style={{ color: "#60a5fa", textDecoration: "underline" }}>Connect AWS</Link> to view live network resources.</p>
          </div>
        </div>
      )}

      {/* Partial Coverage Warning Banner */}
      {coverage === "PARTIAL" && regionalFailures.length > 0 && (
        <div className="net-error-banner" role="alert" style={{ background: "rgba(245, 158, 11, 0.12)", borderColor: "rgba(245, 158, 11, 0.35)", color: "#fbbf24" }}>
          <AlertTriangle size={20} className="net-error-icon text-amber" />
          <div className="net-error-content" style={{ color: "#fef3c7" }}>
            <strong>Multi-Region Discovery Partial Coverage</strong>
            <p>Some regions failed during discovery or were inaccessible: {regionalFailures.map(f => `${f.region} (${f.error_code || 'Error'})`).join(", ")}. Displaying resources from available regions.</p>
          </div>
        </div>
      )}

      {/* ======================================================
          ERROR BANNER
          ====================================================== */}
      {error && (
        <div className="net-error-banner" role="alert">
          <AlertCircle size={20} className="net-error-icon" />
          <div className="net-error-content">
            <strong>Network Inventory Error:</strong>
            <p>{error}</p>
          </div>
          <button
            type="button"
            onClick={() => setError(null)}
            className="net-close-error"
          >
            <X size={16} />
          </button>
        </div>
      )}

      {/* ======================================================
          DATA TABLES / LISTINGS
          ====================================================== */}
      <main className="net-table-container">
        {loading ? (
          <div className="net-loading-state" role="status">
            <RefreshCw size={32} className="spin net-spinner" />
            <p>Querying read-only network inventory from AWS {selectedRegion}...</p>
          </div>
        ) : (
          <>
            {/* 1. SECURITY GROUPS TAB */}
            {activeTab === "security-groups" && (
              securityGroups.length === 0 ? (
                <div className="net-empty-state">
                  <ShieldCheck size={48} className="text-muted" />
                  <h3>No Security Groups Found</h3>
                  <p>No security groups matched your filter criteria in {selectedRegion}.</p>
                </div>
              ) : (
                <table className="net-table">
                  <thead>
                    <tr>
                      <th>Group Name & ID</th>
                      <th>Associated VPC</th>
                      <th>Security Posture</th>
                      <th>Inbound Rules</th>
                      <th>Outbound Rules</th>
                      <th>Key Exposure Signals</th>
                      <th className="text-right">Actions</th>
                    </tr>
                  </thead>
                  <tbody>
                    {securityGroups.map((sg) => (
                      <tr key={sg.group_id}>
                        <td>
                          <div className="net-res-primary">
                            <span className="net-res-name">{sg.name || sg.group_name}</span>
                            <span className="net-res-sub mono">{sg.group_id}</span>
                          </div>
                          {sg.description && (
                            <span className="net-res-desc">{sg.description}</span>
                          )}
                        </td>
                        <td>
                          <span className="mono text-muted">{sg.vpc_id || "EC2-Classic"}</span>
                        </td>
                        <td>{renderPostureBadge(sg.security_posture)}</td>
                        <td>
                          <span className="net-rule-count">
                            <ArrowDownLeft size={14} className="text-blue" />
                            {sg.ingress_rule_count} Ingress
                          </span>
                        </td>
                        <td>
                          <span className="net-rule-count">
                            <ArrowUpRight size={14} className="text-indigo" />
                            {sg.egress_rule_count} Egress
                          </span>
                        </td>
                        <td>
                          <div className="net-exposure-tags">
                            {sg.has_all_traffic_open && (
                              <span className="net-tag net-tag-critical">All Ports Open (0.0.0.0/0)</span>
                            )}
                            {sg.has_open_ssh && (
                              <span className="net-tag net-tag-high">SSH Exposed (:22)</span>
                            )}
                            {sg.has_open_rdp && (
                              <span className="net-tag net-tag-high">RDP Exposed (:3389)</span>
                            )}
                            {!sg.has_all_traffic_open && !sg.has_open_ssh && !sg.has_open_rdp && (
                              <span className="net-tag net-tag-secure">No Critical Exposure</span>
                            )}
                          </div>
                        </td>
                        <td className="text-right">
                          <div className="net-actions-cell">
                            <button
                              type="button"
                              onClick={() => setInspectModal({ isOpen: true, group: sg })}
                              className="net-btn-icon"
                              title="Inspect Ingress and Egress Rules"
                            >
                              <Eye size={16} />
                              <span>Inspect</span>
                            </button>

                            {sg.has_open_ssh && (
                              <button
                                type="button"
                                onClick={() =>
                                  openActionModal(
                                    sg,
                                    "revoke_ssh_ingress",
                                    "Revoke Open SSH Rule (:22)",
                                    null,
                                    "Removes 0.0.0.0/0 and ::/0 unrestricted inbound access to port 22."
                                  )
                                }
                                className="net-btn-remediate"
                                title="Safely revoke public SSH rule"
                              >
                                <Trash2 size={14} />
                                <span>Revoke SSH</span>
                              </button>
                            )}

                            {sg.has_open_rdp && !sg.has_open_ssh && (
                              <button
                                type="button"
                                onClick={() =>
                                  openActionModal(
                                    sg,
                                    "revoke_rdp_ingress",
                                    "Revoke Open RDP Rule (:3389)",
                                    null,
                                    "Removes 0.0.0.0/0 and ::/0 unrestricted inbound access to port 3389."
                                  )
                                }
                                className="net-btn-remediate"
                                title="Safely revoke public RDP rule"
                              >
                                <Trash2 size={14} />
                                <span>Revoke RDP</span>
                              </button>
                            )}
                          </div>
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              )
            )}

            {/* 2. VPCS TAB */}
            {activeTab === "vpcs" && (
              vpcs.length === 0 ? (
                <div className="net-empty-state">
                  <Layers size={48} className="text-muted" />
                  <h3>No VPCs Discovered</h3>
                  <p>No virtual private clouds found in {selectedRegion}.</p>
                </div>
              ) : (
                <table className="net-table">
                  <thead>
                    <tr>
                      <th>VPC Name & ID</th>
                      <th>Primary CIDR Block</th>
                      <th>Secondary CIDRs</th>
                      <th>VPC Type</th>
                      <th>State</th>
                      <th>DHCP Options</th>
                    </tr>
                  </thead>
                  <tbody>
                    {vpcs.map((vpc) => (
                      <tr key={vpc.vpc_id}>
                        <td>
                          <div className="net-res-primary">
                            <span className="net-res-name">{vpc.name}</span>
                            <span className="net-res-sub mono">{vpc.vpc_id}</span>
                          </div>
                        </td>
                        <td>
                          <span className="net-cidr-badge mono">{vpc.cidr_block}</span>
                        </td>
                        <td>
                          {vpc.secondary_cidrs && vpc.secondary_cidrs.length > 0 ? (
                            vpc.secondary_cidrs.map((c) => (
                              <span key={c} className="net-cidr-badge mono secondary">
                                {c}
                              </span>
                            ))
                          ) : (
                            <span className="text-muted">None</span>
                          )}
                        </td>
                        <td>
                          {vpc.is_default ? (
                            <span className="net-badge net-badge-evaluated">Default VPC</span>
                          ) : (
                            <span className="net-badge net-badge-secure">Custom VPC</span>
                          )}
                        </td>
                        <td>
                          <span className="net-state-badge state-available">{vpc.state}</span>
                        </td>
                        <td>
                          <span className="mono text-muted">{vpc.dhcp_options_id}</span>
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              )
            )}

            {/* 3. SUBNETS TAB */}
            {activeTab === "subnets" && (
              subnets.length === 0 ? (
                <div className="net-empty-state">
                  <Server size={48} className="text-muted" />
                  <h3>No Subnets Found</h3>
                  <p>No subnets discovered in {selectedRegion}.</p>
                </div>
              ) : (
                <table className="net-table">
                  <thead>
                    <tr>
                      <th>Subnet Name & ID</th>
                      <th>Parent VPC</th>
                      <th>CIDR Block</th>
                      <th>Availability Zone</th>
                      <th>Available IPs</th>
                      <th>Auto-Assign Public IP</th>
                      <th>Posture</th>
                    </tr>
                  </thead>
                  <tbody>
                    {subnets.map((sub) => (
                      <tr key={sub.subnet_id}>
                        <td>
                          <div className="net-res-primary">
                            <span className="net-res-name">{sub.name}</span>
                            <span className="net-res-sub mono">{sub.subnet_id}</span>
                          </div>
                        </td>
                        <td>
                          <span className="mono text-muted">{sub.vpc_id}</span>
                        </td>
                        <td>
                          <span className="net-cidr-badge mono">{sub.cidr_block}</span>
                        </td>
                        <td>
                          <span className="mono">{sub.availability_zone}</span>
                        </td>
                        <td>
                          <span className="mono">{sub.available_ip_address_count}</span>
                        </td>
                        <td>
                          {sub.map_public_ip_on_launch ? (
                            <span className="net-badge net-badge-risk">
                              <Globe size={12} /> Yes (Public)
                            </span>
                          ) : (
                            <span className="net-badge net-badge-secure">
                              <Lock size={12} /> No (Private)
                            </span>
                          )}
                        </td>
                        <td>{renderPostureBadge(sub.security_posture)}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              )
            )}

            {/* 4. ROUTE TABLES TAB */}
            {activeTab === "route-tables" && (
              routeTables.length === 0 ? (
                <div className="net-empty-state">
                  <Radio size={48} className="text-muted" />
                  <h3>No Route Tables Found</h3>
                  <p>No route tables discovered in {selectedRegion}.</p>
                </div>
              ) : (
                <table className="net-table">
                  <thead>
                    <tr>
                      <th>Route Table ID</th>
                      <th>VPC ID</th>
                      <th>Main Table</th>
                      <th>Internet Routing</th>
                      <th>Routes Count</th>
                      <th>Subnet Associations</th>
                    </tr>
                  </thead>
                  <tbody>
                    {routeTables.map((rt) => (
                      <tr key={rt.route_table_id}>
                        <td>
                          <div className="net-res-primary">
                            <span className="net-res-name">{rt.name}</span>
                            <span className="net-res-sub mono">{rt.route_table_id}</span>
                          </div>
                        </td>
                        <td>
                          <span className="mono text-muted">{rt.vpc_id}</span>
                        </td>
                        <td>
                          {rt.is_main ? (
                            <span className="net-badge net-badge-evaluated">Main Table</span>
                          ) : (
                            <span className="text-muted">Custom</span>
                          )}
                        </td>
                        <td>
                          {rt.has_direct_internet_route ? (
                            <span className="net-badge net-badge-warning">
                              <Globe size={13} /> Direct 0.0.0.0/0 Route
                            </span>
                          ) : (
                            <span className="net-badge net-badge-secure">
                              <Lock size={13} /> Private Routing Only
                            </span>
                          )}
                        </td>
                        <td>
                          <span className="mono">{rt.routes?.length || 0} routes</span>
                        </td>
                        <td>
                          <span className="mono">{rt.associations?.length || 0} associations</span>
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              )
            )}

            {/* 5. GATEWAYS TAB */}
            {activeTab === "gateways" && (
              gateways.length === 0 ? (
                <div className="net-empty-state">
                  <Globe size={48} className="text-muted" />
                  <h3>No Gateways Found</h3>
                  <p>No Internet Gateways or NAT Gateways discovered in {selectedRegion}.</p>
                </div>
              ) : (
                <table className="net-table">
                  <thead>
                    <tr>
                      <th>Gateway ID & Name</th>
                      <th>Gateway Type</th>
                      <th>Attached VPC / Subnet</th>
                      <th>State</th>
                      <th>Public IPs</th>
                    </tr>
                  </thead>
                  <tbody>
                    {gateways.map((gw) => (
                      <tr key={gw.gateway_id}>
                        <td>
                          <div className="net-res-primary">
                            <span className="net-res-name">{gw.name}</span>
                            <span className="net-res-sub mono">{gw.gateway_id}</span>
                          </div>
                        </td>
                        <td>
                          <span className="net-badge net-badge-evaluated">{gw.gateway_type}</span>
                        </td>
                        <td>
                          <div className="mono text-muted">
                            {gw.vpc_ids?.join(", ") || gw.vpc_id || "Unattached"}
                            {gw.subnet_id && ` (${gw.subnet_id})`}
                          </div>
                        </td>
                        <td>
                          <span className="net-state-badge state-available">{gw.state}</span>
                        </td>
                        <td>
                          {gw.public_ips && gw.public_ips.length > 0 ? (
                            gw.public_ips.map((ip) => (
                              <span key={ip} className="mono net-cidr-badge">
                                {ip}
                              </span>
                            ))
                          ) : (
                            <span className="text-muted">N/A</span>
                          )}
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              )
            )}

            {/* 6. VPC ENDPOINTS TAB */}
            {activeTab === "endpoints" && (
              endpoints.length === 0 ? (
                <div className="net-empty-state">
                  <ExternalLink size={48} className="text-muted" />
                  <h3>No VPC Endpoints Discovered</h3>
                  <p>No private VPC endpoints found in {selectedRegion}.</p>
                </div>
              ) : (
                <table className="net-table">
                  <thead>
                    <tr>
                      <th>Endpoint ID & Name</th>
                      <th>Service Name</th>
                      <th>Endpoint Type</th>
                      <th>VPC ID</th>
                      <th>State</th>
                    </tr>
                  </thead>
                  <tbody>
                    {endpoints.map((ep) => (
                      <tr key={ep.vpc_endpoint_id}>
                        <td>
                          <div className="net-res-primary">
                            <span className="net-res-name">{ep.name}</span>
                            <span className="net-res-sub mono">{ep.vpc_endpoint_id}</span>
                          </div>
                        </td>
                        <td>
                          <span className="mono">{ep.service_name}</span>
                        </td>
                        <td>
                          <span className="net-badge net-badge-evaluated">{ep.endpoint_type}</span>
                        </td>
                        <td>
                          <span className="mono text-muted">{ep.vpc_id}</span>
                        </td>
                        <td>
                          <span className="net-state-badge state-available">{ep.state}</span>
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              )
            )}
          </>
        )}
      </main>

      {/* ======================================================
          INSPECTOR MODAL FOR DETAILED SG RULES
          ====================================================== */}
      {inspectModal.isOpen && inspectModal.group && (
        <div className="net-modal-backdrop" role="dialog" aria-modal="true">
          <div className="net-modal-card net-modal-large">
            <div className="net-modal-header">
              <div className="net-modal-title-group">
                <Shield className="text-blue" size={24} />
                <div>
                  <h2>Security Group Rules: {inspectModal.group.name || inspectModal.group.group_id}</h2>
                  <span className="mono text-muted">{inspectModal.group.group_id} • VPC: {inspectModal.group.vpc_id}</span>
                </div>
              </div>
              <button
                type="button"
                onClick={() => setInspectModal({ isOpen: false, group: null })}
                className="net-modal-close"
              >
                <X size={20} />
              </button>
            </div>

            <div className="net-modal-body">
              {/* Ingress Rules Section */}
              <div className="net-rules-section">
                <h3 className="net-rules-heading">
                  <ArrowDownLeft size={16} className="text-blue" />
                  Inbound (Ingress) Rules ({inspectModal.group.ingress_rules?.length || 0})
                </h3>
                {inspectModal.group.ingress_rules?.length === 0 ? (
                  <p className="text-muted">No inbound rules configured.</p>
                ) : (
                  <table className="net-sub-table">
                    <thead>
                      <tr>
                        <th>Protocol</th>
                        <th>Port Range</th>
                        <th>Source (IPv4 / IPv6 / SG)</th>
                        <th>Exposure Level</th>
                        <th className="text-right">Action</th>
                      </tr>
                    </thead>
                    <tbody>
                      {inspectModal.group.ingress_rules.map((rule, idx) => (
                        <tr key={idx} className={rule.is_unrestricted ? "highlight-risk" : ""}>
                          <td>
                            <span className="mono">{rule.protocol === "-1" ? "All Protocols" : rule.protocol.toUpperCase()}</span>
                          </td>
                          <td>
                            <span className="mono">
                              {rule.protocol === "-1"
                                ? "All Ports"
                                : rule.from_port === rule.to_port
                                ? rule.from_port
                                : `${rule.from_port}-${rule.to_port}`}
                            </span>
                          </td>
                          <td>
                            <div className="net-source-tags">
                              {rule.ip_ranges?.map((ip) => (
                                <span key={ip} className={`mono net-cidr-badge ${ip === "0.0.0.0/0" ? "badge-danger" : ""}`}>
                                  {ip}
                                </span>
                              ))}
                              {rule.ipv6_ranges?.map((ip6) => (
                                <span key={ip6} className={`mono net-cidr-badge ${ip6 === "::/0" ? "badge-danger" : ""}`}>
                                  {ip6}
                                </span>
                              ))}
                              {rule.user_id_group_pairs?.map((p) => (
                                <span key={p.group_id} className="mono net-cidr-badge secondary">
                                  {p.group_id}
                                </span>
                              ))}
                            </div>
                          </td>
                          <td>
                            {rule.risk_level === "CRITICAL" && (
                              <span className="net-badge net-badge-critical">CRITICAL UNRESTRICTED</span>
                            )}
                            {rule.risk_level === "HIGH" && (
                              <span className="net-badge net-badge-high">{rule.risk_description}</span>
                            )}
                            {rule.risk_level === "MEDIUM" && (
                              <span className="net-badge net-badge-risk">{rule.risk_description}</span>
                            )}
                            {rule.risk_level === "LOW" && (
                              <span className="net-badge net-badge-secure">Restricted Source</span>
                            )}
                          </td>
                          <td className="text-right">
                            {rule.is_unrestricted && (
                              <button
                                type="button"
                                onClick={() => {
                                  setInspectModal({ isOpen: false, group: null });
                                  const actionKey =
                                    rule.protocol === "-1"
                                      ? "revoke_all_traffic_ingress"
                                      : rule.from_port === 22
                                      ? "revoke_ssh_ingress"
                                      : rule.from_port === 3389
                                      ? "revoke_rdp_ingress"
                                      : "revoke_ingress_rule";
                                  openActionModal(
                                    inspectModal.group,
                                    actionKey,
                                    `Revoke Ingress Rule (${rule.protocol.toUpperCase()} :${rule.from_port})`,
                                    {
                                      protocol: rule.protocol,
                                      from_port: rule.from_port,
                                      to_port: rule.to_port,
                                      cidr: rule.ip_ranges?.[0] || "",
                                      cidr_ipv6: rule.ipv6_ranges?.[0] || "",
                                    },
                                    rule.risk_description
                                  );
                                }}
                                className="net-btn-remediate-sm"
                              >
                                Revoke
                              </button>
                            )}
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                )}
              </div>

              {/* Egress Rules Section */}
              <div className="net-rules-section" style={{ marginTop: "1.5rem" }}>
                <h3 className="net-rules-heading">
                  <ArrowUpRight size={16} className="text-indigo" />
                  Outbound (Egress) Rules ({inspectModal.group.egress_rules?.length || 0})
                </h3>
                {inspectModal.group.egress_rules?.length === 0 ? (
                  <p className="text-muted">No outbound rules configured.</p>
                ) : (
                  <table className="net-sub-table">
                    <thead>
                      <tr>
                        <th>Protocol</th>
                        <th>Port Range</th>
                        <th>Destination</th>
                        <th>Notes</th>
                      </tr>
                    </thead>
                    <tbody>
                      {inspectModal.group.egress_rules.map((rule, idx) => (
                        <tr key={idx}>
                          <td>
                            <span className="mono">{rule.protocol === "-1" ? "All Protocols" : rule.protocol.toUpperCase()}</span>
                          </td>
                          <td>
                            <span className="mono">{rule.protocol === "-1" ? "All Ports" : `${rule.from_port}-${rule.to_port}`}</span>
                          </td>
                          <td>
                            <div className="net-source-tags">
                              {rule.ip_ranges?.map((ip) => (
                                <span key={ip} className="mono net-cidr-badge">
                                  {ip}
                                </span>
                              ))}
                              {rule.ipv6_ranges?.map((ip6) => (
                                <span key={ip6} className="mono net-cidr-badge">
                                  {ip6}
                                </span>
                              ))}
                            </div>
                          </td>
                          <td>
                            <span className="text-muted">{rule.risk_description || "Standard Outbound"}</span>
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                )}
              </div>
            </div>

            <div className="net-modal-footer">
              <Link to="/security-graph" className="net-link-btn">
                <Network size={15} /> View in Security Graph
              </Link>
              <button
                type="button"
                onClick={() => setInspectModal({ isOpen: false, group: null })}
                className="net-btn-secondary"
              >
                Close Inspector
              </button>
            </div>
          </div>
        </div>
      )}

      {/* ======================================================
          REMEDIATION CONFIRMATION MODAL
          ====================================================== */}
      {actionModal.isOpen && actionModal.group && (
        <div className="net-modal-backdrop" role="dialog" aria-modal="true">
          <div className="net-modal-card">
            <div className="net-modal-header">
              <div className="net-modal-title-group">
                <AlertTriangle className="text-amber" size={24} />
                <div>
                  <h2>Confirm Security Group Rule Remediation</h2>
                  <span className="mono text-muted">{actionModal.group.group_id} ({actionModal.group.name})</span>
                </div>
              </div>
              <button
                type="button"
                onClick={closeActionModal}
                disabled={actionExecuting}
                className="net-modal-close"
              >
                <X size={20} />
              </button>
            </div>

            <div className="net-modal-body">
              <div className="net-confirm-details-box">
                <div className="net-confirm-row">
                  <span className="net-confirm-label">Target Account:</span>
                  <span className="net-confirm-val mono">{currentAccount?.account_name || selectedAccountId}</span>
                </div>
                <div className="net-confirm-row">
                  <span className="net-confirm-label">AWS Region:</span>
                  <span className="net-confirm-val mono">{selectedRegion}</span>
                </div>
                <div className="net-confirm-row">
                  <span className="net-confirm-label">Security Group:</span>
                  <span className="net-confirm-val mono">{actionModal.group.group_id}</span>
                </div>
                <div className="net-confirm-row">
                  <span className="net-confirm-label">VPC ID:</span>
                  <span className="net-confirm-val mono">{actionModal.group.vpc_id}</span>
                </div>
                <div className="net-confirm-row">
                  <span className="net-confirm-label">Proposed Action:</span>
                  <span className="net-confirm-val text-amber font-semibold">{actionModal.actionLabel}</span>
                </div>
              </div>

              <div className="net-confirm-impact-box">
                <h4>
                  <ShieldCheck size={16} className="text-emerald" /> Security Benefit:
                </h4>
                <p>
                  Eliminates public Internet exposure by revoking the overly permissive rule from AWS EC2.
                </p>

                <h4 style={{ marginTop: "0.75rem" }}>
                  <AlertCircle size={16} className="text-amber" /> Potential Connectivity Impact:
                </h4>
                <p>
                  External connections relying on this public ingress rule will be disconnected. Ensure trusted access is configured before proceeding.
                </p>
              </div>

              {actionFeedback && (
                <div className={`net-feedback-banner ${actionFeedback.type}`}>
                  {actionFeedback.type === "success" ? (
                    <CheckCircle2 size={18} />
                  ) : (
                    <AlertCircle size={18} />
                  )}
                  <span>{actionFeedback.message}</span>
                </div>
              )}

              <label className="net-confirm-checkbox-label">
                <input
                  type="checkbox"
                  checked={actionConfirmed}
                  onChange={(e) => setActionConfirmed(e.target.checked)}
                  disabled={actionExecuting}
                />
                <span>
                  I explicitly authorize CloudGuardAI to revoke this security group rule in AWS.
                </span>
              </label>
            </div>

            <div className="net-modal-footer">
              <button
                type="button"
                onClick={closeActionModal}
                disabled={actionExecuting}
                className="net-btn-secondary"
              >
                Cancel
              </button>
              <button
                type="button"
                onClick={handleExecuteAction}
                disabled={!actionConfirmed || actionExecuting}
                className="net-btn-danger"
              >
                {actionExecuting ? (
                  <>
                    <RefreshCw size={16} className="spin" />
                    <span>Revoking Rule...</span>
                  </>
                ) : (
                  <>
                    <Trash2 size={16} />
                    <span>Execute Rule Revocation</span>
                  </>
                )}
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
