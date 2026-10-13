import { useCallback, useEffect, useId, useMemo, useRef, useState } from "react";
import { Link } from "react-router-dom";
import {
  Users,
  Key,
  Shield,
  FileText,
  AlertTriangle,
  ChevronLeft,
  ChevronRight,
  Activity,
  CheckCircle2,
  AlertCircle,
  HelpCircle,
  RefreshCw,
  Search,
  Lock,
  X
} from "lucide-react";
import {
  getAWSAccounts,
  getIAMInventory,
  controlIAMResource,
} from "../services/awsService";
import "./IAMManagement.css";

export default function IAMManagement() {
  const accountSelectId = useId();
  const searchInputId = useId();
  const confirmCheckId = useId();

  // Accounts state
  const [accounts, setAccounts] = useState([]);
  const [accountsLoading, setAccountsLoading] = useState(true);
  const [selectedAccountId, setSelectedAccountId] = useState("");

  // Inventory state
  const [inventory, setInventory] = useState(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState(null);
  const [lastRefreshed, setLastRefreshed] = useState(null);
  const [activeTab, setActiveTab] = useState("users"); // "users" | "roles" | "policies"

  // Search
  const [searchTerm, setSearchTerm] = useState("");

  // Action / Mutation Modal state
  const [actionModal, setActionModal] = useState({
    isOpen: false,
    resource: null,
    resourceType: null,
    action: null, 
    parameters: null,
  });
  const [actionConfirmed, setActionConfirmed] = useState(false);
  const [actionExecuting, setActionExecuting] = useState(false);
  const [actionFeedback, setActionFeedback] = useState(null); // { type: 'success'|'error', message: '' }

  const latestRequestIdRef = useRef(0);

  // Load Accounts
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
          "Failed to load connected AWS accounts."
        );
      } finally {
        if (isMounted) setAccountsLoading(false);
      }
    }
    loadAccounts();
    return () => { isMounted = false; };
  }, []);

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

  // Fetch Inventory
  const fetchInventory = useCallback(async () => {
    if (!selectedAccountId) return;
    const requestId = ++latestRequestIdRef.current;
    setLoading(true);
    setError(null);

    try {
      const data = await getIAMInventory(selectedAccountId);
      if (requestId !== latestRequestIdRef.current) return;
      setInventory(data.inventory);
      setLastRefreshed(new Date());
    } catch (err) {
      if (requestId !== latestRequestIdRef.current) return;
      const status = err?.response?.status;
      const detail = err?.response?.data?.detail;
      if (status === 403) setError(detail || "AWS Access Denied.");
      else if (status === 404) setError("Connected AWS Account not found.");
      else setError(detail || err?.message || "Failed to communicate with AWS IAM service.");
    } finally {
      if (requestId === latestRequestIdRef.current) setLoading(false);
    }
  }, [selectedAccountId]);

  useEffect(() => {
    fetchInventory();
  }, [fetchInventory]);

  const handleRefresh = () => {
    setSearchTerm("");
    fetchInventory();
  };

  const openModal = (resource, resourceType, action, parameters = null) => {
    setActionFeedback(null);
    setActionConfirmed(false);
    setActionModal({
      isOpen: true,
      resource,
      resourceType,
      action,
      parameters,
    });
  };

  const closeModal = () => {
    if (actionExecuting) return;
    setActionModal({ isOpen: false, resource: null, resourceType: null, action: null, parameters: null });
    setActionConfirmed(false);
    setActionFeedback(null);
  };

  const handleExecuteAction = async () => {
    if (!actionConfirmed) return;
    setActionExecuting(true);
    setActionFeedback(null);
    try {
      let resId = "";
      if (actionModal.resourceType === "user") {
        resId = actionModal.action === "disable_access_key" ? actionModal.parameters.access_key_id : actionModal.resource.user_name;
      } else if (actionModal.resourceType === "role") {
        resId = actionModal.resource.role_name;
      } else if (actionModal.resourceType === "policy") {
        resId = actionModal.resource.policy_name;
      }

      await controlIAMResource(
        selectedAccountId,
        resId,
        {
          action: actionModal.action,
          resource_type: actionModal.resourceType,
          parameters: actionModal.parameters,
          confirmed: true,
        }
      );
      
      setActionFeedback({
        type: "success",
        message: `Successfully executed ${actionModal.action}.`,
      });
      setTimeout(() => {
        closeModal();
        handleRefresh();
      }, 2000);
    } catch (err) {
      setActionFeedback({
        type: "error",
        message: err?.response?.data?.detail || "Execution failed. Check your permissions and try again.",
      });
    } finally {
      setActionExecuting(false);
    }
  };

  const filteredUsers = useMemo(() => {
    if (!inventory?.users) return [];
    if (!searchTerm) return inventory.users;
    return inventory.users.filter(u => u.user_name.toLowerCase().includes(searchTerm.toLowerCase()));
  }, [inventory, searchTerm]);

  const filteredRoles = useMemo(() => {
    if (!inventory?.roles) return [];
    if (!searchTerm) return inventory.roles;
    return inventory.roles.filter(r => r.role_name.toLowerCase().includes(searchTerm.toLowerCase()));
  }, [inventory, searchTerm]);

  const filteredPolicies = useMemo(() => {
    if (!inventory?.policies) return [];
    if (!searchTerm) return inventory.policies;
    return inventory.policies.filter(p => p.policy_name.toLowerCase().includes(searchTerm.toLowerCase()));
  }, [inventory, searchTerm]);

  return (
    <div className="iam-management">
      <div className="page-header">
        <div className="header-content">
          <h1>IAM Management</h1>
          <p>Read-only inventory and secure remediation for AWS Identity and Access Management.</p>
        </div>
      </div>

      <div className="controls-bar">
        <div className="account-selector">
          <label htmlFor={accountSelectId} className="visually-hidden">AWS Account</label>
          <select
            id={accountSelectId}
            value={selectedAccountId}
            onChange={(e) => setSelectedAccountId(e.target.value)}
            disabled={accountsLoading || loading}
            aria-label="Select AWS Account"
          >
            {accountsLoading ? (
              <option value="">Loading accounts...</option>
            ) : accounts.length === 0 ? (
              <option value="">No connected accounts</option>
            ) : (
              accounts.map((acc) => (
                <option key={acc._id} value={acc._id || acc.aws_account_id}>
                  {acc.account_name} ({acc.aws_account_id || acc.account})
                </option>
              ))
            )}
          </select>
        </div>
        
        <div className="controls-actions">
          <div className="search-box">
            <Search size={18} />
            <input
              id={searchInputId}
              type="text"
              placeholder="Search resource name..."
              value={searchTerm}
              onChange={(e) => setSearchTerm(e.target.value)}
              disabled={loading || !inventory}
            />
          </div>
          <button
            onClick={handleRefresh}
            className={`refresh-btn ${loading ? "spinning" : ""}`}
            disabled={loading || !selectedAccountId}
            title="Refresh Inventory"
          >
            <RefreshCw size={18} />
          </button>
        </div>
      </div>

      {error ? (
        <div className="inventory-error">
          <AlertCircle size={40} />
          <h3>Error Fetching Inventory</h3>
          <p>{error}</p>
          <button onClick={handleRefresh} className="retry-btn">Try Again</button>
        </div>
      ) : loading && !inventory ? (
        <div className="inventory-loading">
          <RefreshCw size={40} className="spinning" />
          <p>Scanning IAM environment...</p>
        </div>
      ) : inventory ? (
        <>
          <div className="iam-summary-cards">
            <div className={`summary-card ${activeTab === 'users' ? 'active' : ''}`} onClick={() => setActiveTab('users')}>
              <Users size={24} className="icon-blue" />
              <div className="summary-info">
                <span className="summary-value">{inventory.total_users}</span>
                <span className="summary-label">Users</span>
              </div>
            </div>
            <div className={`summary-card ${activeTab === 'roles' ? 'active' : ''}`} onClick={() => setActiveTab('roles')}>
              <Shield size={24} className="icon-green" />
              <div className="summary-info">
                <span className="summary-value">{inventory.total_roles}</span>
                <span className="summary-label">Roles</span>
              </div>
            </div>
            <div className={`summary-card ${activeTab === 'policies' ? 'active' : ''}`} onClick={() => setActiveTab('policies')}>
              <FileText size={24} className="icon-purple" />
              <div className="summary-info">
                <span className="summary-value">{inventory.total_policies}</span>
                <span className="summary-label">Policies (Local)</span>
              </div>
            </div>
          </div>

          <div className="inventory-container">
            <div className="inventory-header">
              <h2>{activeTab === 'users' ? 'IAM Users' : activeTab === 'roles' ? 'IAM Roles' : 'Customer Managed Policies'}</h2>
              {lastRefreshed && (
                <span className="last-refreshed">
                  <Clock size={14} /> Last refreshed: {lastRefreshed.toLocaleTimeString()}
                </span>
              )}
            </div>

            <div className="table-responsive">
              <table className="iam-table">
                {activeTab === 'users' && (
                  <>
                    <thead>
                      <tr>
                        <th>Username</th>
                        <th>MFA Enabled</th>
                        <th>Console Access</th>
                        <th>Access Keys</th>
                        <th>Actions</th>
                      </tr>
                    </thead>
                    <tbody>
                      {filteredUsers.length === 0 ? (
                        <tr><td colSpan="5" className="empty-state">No users found.</td></tr>
                      ) : (
                        filteredUsers.map((user) => (
                          <tr key={user.user_name}>
                            <td className="resource-name">{user.user_name}</td>
                            <td>
                              {user.mfa_enabled ? (
                                <span className="badge badge-success"><CheckCircle2 size={14} /> Yes</span>
                              ) : (
                                <span className="badge badge-danger"><AlertCircle size={14} /> No</span>
                              )}
                            </td>
                            <td>
                              {user.console_access ? (
                                <span className="badge badge-warning">Enabled</span>
                              ) : (
                                <span className="badge badge-secondary">Disabled</span>
                              )}
                            </td>
                            <td>
                              {user.access_keys.length > 0 ? (
                                <ul className="access-key-list">
                                  {user.access_keys.map(k => (
                                    <li key={k.access_key_id} className="access-key-item">
                                      <Key size={14} /> {k.access_key_id} 
                                      <span className={`status-dot ${k.status.toLowerCase()}`}></span>
                                      {k.status === 'Active' && (
                                        <button className="btn-sm btn-danger" onClick={() => openModal(user, "user", "disable_access_key", { username: user.user_name, access_key_id: k.access_key_id })}>Disable</button>
                                      )}
                                    </li>
                                  ))}
                                </ul>
                              ) : (
                                <span className="text-muted">No keys</span>
                              )}
                            </td>
                            <td>
                              <button className="btn-sm btn-outline" onClick={() => {}}>View Details</button>
                            </td>
                          </tr>
                        ))
                      )}
                    </tbody>
                  </>
                )}

                {activeTab === 'roles' && (
                  <>
                    <thead>
                      <tr>
                        <th>Role Name</th>
                        <th>ARN</th>
                        <th>Creation Date</th>
                        <th>Actions</th>
                      </tr>
                    </thead>
                    <tbody>
                      {filteredRoles.length === 0 ? (
                        <tr><td colSpan="4" className="empty-state">No roles found.</td></tr>
                      ) : (
                        filteredRoles.map((role) => (
                          <tr key={role.role_name}>
                            <td className="resource-name">{role.role_name}</td>
                            <td className="monospace">{role.arn}</td>
                            <td>{role.create_date ? new Date(role.create_date).toLocaleDateString() : 'N/A'}</td>
                            <td>
                              <button className="btn-sm btn-outline">View Details</button>
                            </td>
                          </tr>
                        ))
                      )}
                    </tbody>
                  </>
                )}

                {activeTab === 'policies' && (
                  <>
                    <thead>
                      <tr>
                        <th>Policy Name</th>
                        <th>Attachments</th>
                        <th>Creation Date</th>
                        <th>Actions</th>
                      </tr>
                    </thead>
                    <tbody>
                      {filteredPolicies.length === 0 ? (
                        <tr><td colSpan="4" className="empty-state">No policies found.</td></tr>
                      ) : (
                        filteredPolicies.map((policy) => (
                          <tr key={policy.policy_name}>
                            <td className="resource-name">{policy.policy_name}</td>
                            <td>
                              <span className="badge badge-info">{policy.attachment_count} entities</span>
                            </td>
                            <td>{policy.create_date ? new Date(policy.create_date).toLocaleDateString() : 'N/A'}</td>
                            <td>
                              <button className="btn-sm btn-outline">View Details</button>
                            </td>
                          </tr>
                        ))
                      )}
                    </tbody>
                  </>
                )}
              </table>
            </div>
          </div>
        </>
      ) : null}

      {/* ACTION MODAL */}
      {actionModal.isOpen && (
        <div className="modal-overlay">
          <div className="modal-content action-modal">
            <div className="modal-header warning-header">
              <h3>Confirm IAM Action</h3>
              <button className="close-btn" onClick={closeModal} disabled={actionExecuting} aria-label="Close modal">
                <X size={20} />
              </button>
            </div>
            
            <div className="modal-body">
              <div className="warning-banner">
                <AlertTriangle size={24} />
                <div>
                  <strong>Destructive Action Warning</strong>
                  <p>You are about to execute a security control that will alter IAM state in the connected AWS account.</p>
                </div>
              </div>

              <div className="action-details">
                <div className="detail-row">
                  <span>Target Account:</span>
                  <strong>{currentAccount?.account_name} ({currentAccount?.aws_account_id})</strong>
                </div>
                <div className="detail-row">
                  <span>Action:</span>
                  <strong>{actionModal.action.toUpperCase()}</strong>
                </div>
                <div className="detail-row">
                  <span>Resource:</span>
                  <strong>{actionModal.resourceType === 'user' && actionModal.action === 'disable_access_key' ? actionModal.parameters.access_key_id : actionModal.resource?.user_name || actionModal.resource?.role_name || actionModal.resource?.policy_name}</strong>
                </div>
              </div>

              {actionFeedback && (
                <div className={`feedback-banner ${actionFeedback.type}`}>
                  {actionFeedback.type === 'success' ? <CheckCircle2 size={20} /> : <AlertCircle size={20} />}
                  <span>{actionFeedback.message}</span>
                </div>
              )}

              <div className="confirmation-checkbox">
                <input
                  type="checkbox"
                  id={confirmCheckId}
                  checked={actionConfirmed}
                  onChange={(e) => setActionConfirmed(e.target.checked)}
                  disabled={actionExecuting || actionFeedback?.type === 'success'}
                />
                <label htmlFor={confirmCheckId}>
                  I confirm that I want to {actionModal.action.replace(/_/g, ' ')} for this resource. I understand this may disrupt access for applications or users depending on it.
                </label>
              </div>
            </div>

            <div className="modal-footer">
              <button 
                className="btn-cancel" 
                onClick={closeModal} 
                disabled={actionExecuting || actionFeedback?.type === 'success'}
              >
                Cancel
              </button>
              <button
                className={`btn-execute ${actionExecuting ? 'executing' : ''}`}
                onClick={handleExecuteAction}
                disabled={!actionConfirmed || actionExecuting || actionFeedback?.type === 'success'}
              >
                {actionExecuting ? (
                  <><RefreshCw size={16} className="spinning" /> Executing...</>
                ) : (
                  <><Lock size={16} /> Execute Action</>
                )}
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
