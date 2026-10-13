import { useCallback, useEffect, useId, useMemo, useState } from "react";
import {
  AlertTriangle,
  Check,
  Database,
  FileText,
  HardDrive,
  Info,
  Key,
  Lock,
  Network,
  RefreshCw,
  Server,
  ShieldAlert,
  ShieldCheck,
} from "lucide-react";
import api from "../services/api";
import { getAWSAccounts } from "../services/awsService";
import {
  getRemediationSettings,
  updateRemediationSettings,
} from "../services/remediationService";
import "./RemediationGovernanceSettings.css";

const REMEDIATION_SERVICES = [
  {
    key: "ec2",
    name: "Amazon EC2",
    shortName: "EC2",
    icon: Server,
    color: "#f59e0b",
    description:
      "Permits stopping, starting, and rebooting EC2 instances via automated remediation playbooks and direct resource controls.",
    actions: ["EC2_STOP_INSTANCE", "EC2 Start / Stop / Reboot Controls"],
  },
  {
    key: "s3",
    name: "Amazon S3",
    shortName: "S3",
    icon: HardDrive,
    color: "#10b981",
    description:
      "Permits enabling S3 Block Public Access (BPA), enforcing bucket encryption, and enabling versioning on storage buckets.",
    actions: ["S3_ENABLE_BLOCK_PUBLIC_ACCESS", "S3 BPA Enforcement"],
  },
  {
    key: "vpc",
    name: "VPC & Security Groups",
    shortName: "VPC / SG",
    icon: Network,
    color: "#6366f1",
    description:
      "Permits revoking insecure ingress rules (e.g., 0.0.0.0/0 on SSH port 22 or RDP port 3389) across security groups.",
    actions: ["VPC_REMOVE_INSECURE_INGRESS", "Security Group Ingress Revocation"],
  },
  {
    key: "rds",
    name: "Amazon RDS",
    shortName: "RDS",
    icon: Database,
    color: "#3b82f6",
    description:
      "Permits stopping, starting database instances, and disabling public accessibility on RDS DB instances.",
    actions: ["RDS_DISABLE_PUBLIC_ACCESS", "RDS Instance Start / Stop"],
  },
  {
    key: "iam",
    name: "AWS IAM",
    shortName: "IAM",
    icon: Key,
    color: "#ec4899",
    description:
      "Permits deactivating compromised or inactive access keys and detaching overly permissive user policies.",
    actions: ["IAM_DISABLE_ACCESS_KEY", "IAM Key Deactivation"],
  },
  {
    key: "cloudtrail",
    name: "AWS CloudTrail",
    shortName: "CloudTrail",
    icon: FileText,
    color: "#06b6d4",
    description:
      "Permits starting trail logging and re-activating stopped multi-region audit trails to maintain security compliance.",
    actions: ["CLOUDTRAIL_ENABLE_LOGGING", "CloudTrail Logging Activation"],
  },
];

const DEFAULT_SETTINGS = {
  ec2: false,
  s3: false,
  vpc: false,
  rds: false,
  iam: false,
  cloudtrail: false,
};

export default function RemediationGovernanceSettings({ organizationId, refreshTrigger }) {
  const accountSelectId = useId();

  // Accounts state
  const [accounts, setAccounts] = useState([]);
  const [accountsLoading, setAccountsLoading] = useState(true);
  const [accountsError, setAccountsError] = useState("");
  const [selectedAccountId, setSelectedAccountId] = useState("");

  // Role state
  const [userRole, setUserRole] = useState("viewer");
  const [roleLoading, setRoleLoading] = useState(true);

  // Settings state (Fail-closed: default to all disabled)
  const [settings, setSettings] = useState(DEFAULT_SETTINGS);
  const [savedSettings, setSavedSettings] = useState(DEFAULT_SETTINGS);
  const [settingsLoading, setSettingsLoading] = useState(false);
  const [settingsError, setSettingsError] = useState("");
  const [lastUpdated, setLastUpdated] = useState(null);
  const [updatedBy, setUpdatedBy] = useState(null);
  const [existsInDb, setExistsInDb] = useState(false);

  // Mutation state
  const [saving, setSaving] = useState(false);
  const [saveSuccess, setSaveSuccess] = useState("");
  const [saveError, setSaveError] = useState("");

  // ============================================================
  // RESOLVE USER ROLE
  // ============================================================
  const resolveRole = useCallback(async () => {
    try {
      setRoleLoading(true);
      const user = JSON.parse(localStorage.getItem("user") || "{}");
      const orgId = organizationId || user.organization || user.organization_id;
      const userId = user._id || user.id || user.user_id;

      let determinedRole = String(user.role || "viewer").toLowerCase().trim();

      if (orgId && userId) {
        try {
          const res = await api.get(`/organizations/${orgId}/members`);
          const memberList = res.data?.members || [];
          const cur = memberList.find(
            (m) => String(m.user_id) === String(userId)
          );
          if (cur?.role) {
            determinedRole = String(cur.role).toLowerCase().trim();
          }
        } catch {
          // Fall back to user.role from session if members endpoint fails
        }
      }

      setUserRole(determinedRole);
    } catch {
      setUserRole("viewer");
    } finally {
      setRoleLoading(false);
    }
  }, [organizationId]);

  useEffect(() => {
    resolveRole();
  }, [resolveRole]);

  const isOwnerOrAdmin = useMemo(() => {
    return userRole === "owner" || userRole === "admin" || userRole === "administrator";
  }, [userRole]);

  // ============================================================
  // LOAD CONNECTED AWS ACCOUNTS
  // ============================================================
  const loadAccounts = useCallback(async () => {
    try {
      setAccountsLoading(true);
      setAccountsError("");
      const data = await getAWSAccounts();
      const list = Array.isArray(data) ? data : [];
      setAccounts(list);

      if (list.length > 0) {
        // Keep existing selection if valid, else pick first connected account
        setSelectedAccountId((prev) => {
          const exists = list.some(
            (a) => (a._id || a.account_id || a.id) === prev
          );
          if (exists) return prev;
          const first = list[0];
          return first._id || first.account_id || first.id || "";
        });
      } else {
        setSelectedAccountId("");
      }
    } catch (err) {
      setAccountsError(
        err.response?.data?.detail ||
          err.message ||
          "Unable to load connected AWS accounts."
      );
    } finally {
      setAccountsLoading(false);
    }
  }, []);

  useEffect(() => {
    loadAccounts();
  }, [loadAccounts, refreshTrigger]);

  // ============================================================
  // LOAD REMEDIATION SETTINGS FOR SELECTED ACCOUNT
  // ============================================================
  const loadSettingsForAccount = useCallback(async (accId) => {
    if (!accId) {
      setSettings(DEFAULT_SETTINGS);
      setSavedSettings(DEFAULT_SETTINGS);
      setExistsInDb(false);
      setLastUpdated(null);
      setUpdatedBy(null);
      return;
    }

    try {
      setSettingsLoading(true);
      setSettingsError("");
      setSaveSuccess("");
      setSaveError("");

      const res = await getRemediationSettings(accId);
      const incoming = res?.services || DEFAULT_SETTINGS;

      // Fail-closed guarantee: ensure all 6 keys are boolean
      const sanitized = {
        ec2: Boolean(incoming.ec2),
        s3: Boolean(incoming.s3),
        vpc: Boolean(incoming.vpc),
        rds: Boolean(incoming.rds),
        iam: Boolean(incoming.iam),
        cloudtrail: Boolean(incoming.cloudtrail),
      };

      setSettings(sanitized);
      setSavedSettings(sanitized);
      setExistsInDb(Boolean(res?.exists));
      setLastUpdated(res?.updated_at || null);
      setUpdatedBy(res?.updated_by || null);
    } catch (err) {
      const status = err.response?.status;
      let msg = "Failed to load remediation governance settings.";

      if (status === 403) {
        msg = "Access Denied: You do not have permission to view remediation settings for this organization.";
      } else if (status === 404) {
        msg = "Connected AWS account not found or does not belong to your organization.";
      } else if (err.response?.data?.detail) {
        msg = err.response.data.detail;
      } else if (err.message) {
        msg = err.message;
      }

      setSettingsError(msg);
      // Fail-closed fallback: never silently enable anything
      setSettings(DEFAULT_SETTINGS);
      setSavedSettings(DEFAULT_SETTINGS);
    } finally {
      setSettingsLoading(false);
    }
  }, []);

  useEffect(() => {
    if (selectedAccountId) {
      loadSettingsForAccount(selectedAccountId);
    }
  }, [selectedAccountId, loadSettingsForAccount, refreshTrigger]);

  // Find currently selected account object
  const currentAccount = useMemo(() => {
    return (
      accounts.find(
        (a) => (a._id || a.account_id || a.id) === selectedAccountId
      ) || null
    );
  }, [accounts, selectedAccountId]);

  const isDisconnected = currentAccount?.status && currentAccount.status !== "connected";

  // Check if user has pending unsaved changes
  const hasChanges = useMemo(() => {
    return REMEDIATION_SERVICES.some(
      (svc) => Boolean(settings[svc.key]) !== Boolean(savedSettings[svc.key])
    );
  }, [settings, savedSettings]);

  // Number of currently enabled services
  const enabledCount = useMemo(() => {
    return Object.values(settings).filter(Boolean).length;
  }, [settings]);

  // ============================================================
  // HANDLERS
  // ============================================================
  const handleToggle = (serviceKey, checked) => {
    if (!isOwnerOrAdmin || saving || settingsLoading || isDisconnected) {
      return;
    }
    setSaveSuccess("");
    setSaveError("");
    setSettings((prev) => ({
      ...prev,
      [serviceKey]: Boolean(checked),
    }));
  };

  const handleReset = () => {
    setSettings(savedSettings);
    setSaveSuccess("");
    setSaveError("");
  };

  const handleSave = async () => {
    if (!isOwnerOrAdmin) {
      setSaveError("Only organization Owners and Admins can update remediation settings.");
      return;
    }
    if (!selectedAccountId) {
      setSaveError("Please select a valid connected AWS account.");
      return;
    }
    if (isDisconnected) {
      setSaveError("Cannot update remediation settings for a disconnected AWS account.");
      return;
    }

    try {
      setSaving(true);
      setSaveSuccess("");
      setSaveError("");

      const payload = {
        ec2: Boolean(settings.ec2),
        s3: Boolean(settings.s3),
        vpc: Boolean(settings.vpc),
        rds: Boolean(settings.rds),
        iam: Boolean(settings.iam),
        cloudtrail: Boolean(settings.cloudtrail),
      };

      const res = await updateRemediationSettings(selectedAccountId, payload);

      const updated = res?.services || payload;
      const sanitized = {
        ec2: Boolean(updated.ec2),
        s3: Boolean(updated.s3),
        vpc: Boolean(updated.vpc),
        rds: Boolean(updated.rds),
        iam: Boolean(updated.iam),
        cloudtrail: Boolean(updated.cloudtrail),
      };

      setSettings(sanitized);
      setSavedSettings(sanitized);
      setExistsInDb(true);
      setLastUpdated(res?.updated_at || new Date().toISOString());
      setUpdatedBy(res?.updated_by || null);

      setSaveSuccess(
        `Remediation governance settings successfully saved for ${
          currentAccount?.account_name || "AWS Account"
        }.`
      );
    } catch (err) {
      const status = err.response?.status;
      let msg = "Failed to update remediation governance settings.";

      if (status === 403) {
        msg = "Permission Denied: Only organization Owners and Admins are authorized to update remediation settings.";
      } else if (status === 404) {
        msg = "Account Not Found: This AWS account was not found or is not associated with your organization.";
      } else if (status === 400) {
        msg = err.response?.data?.detail || "Invalid request or disconnected account.";
      } else if (status === 422) {
        msg = "Validation Error: Unrecognized service key or invalid payload format.";
      } else if (err.response?.data?.detail) {
        msg = err.response.data.detail;
      } else if (err.message) {
        msg = err.message;
      }

      setSaveError(msg);
    } finally {
      setSaving(false);
    }
  };

  const formatDate = (val) => {
    if (!val) return "Not available";
    const d = new Date(val);
    if (Number.isNaN(d.getTime())) return "Not available";
    return d.toLocaleString(undefined, {
      day: "2-digit",
      month: "short",
      year: "numeric",
      hour: "2-digit",
      minute: "2-digit",
    });
  };

  // ============================================================
  // RENDER
  // ============================================================
  return (
    <section className="remediation-gov-card" aria-labelledby="remediation-gov-title">
      {/* ----------------------------------------------------
          CARD HEADER
          ----------------------------------------------------- */}
      <div className="remediation-gov-header">
        <div>
          <p className="remediation-gov-eyebrow">
            SECURITY GOVERNANCE & CONTROL
          </p>
          <h2 id="remediation-gov-title" className="remediation-gov-title">
            Remediation Policy Controls
          </h2>
          <p className="remediation-gov-subtitle">
            Configure per-service automated remediation and direct control permissions for your connected AWS accounts.
          </p>
        </div>

        <div className="remediation-gov-header-actions">
          {/* Role Badge */}
          <span
            className={`remediation-gov-role-badge ${
              isOwnerOrAdmin ? "role-admin" : "role-viewer"
            }`}
            title={`Your active organization role: ${userRole.toUpperCase()}`}
          >
            {isOwnerOrAdmin ? (
              <ShieldCheck size={13} />
            ) : (
              <Lock size={13} />
            )}
            Role: {userRole.charAt(0).toUpperCase() + userRole.slice(1)}
          </span>

          {/* Account Selector */}
          {accounts.length > 0 && (
            <div className="remediation-gov-select-wrapper">
              <label htmlFor={accountSelectId} className="sr-only">
                Select Connected AWS Account
              </label>
              <select
                id={accountSelectId}
                className="remediation-gov-account-select"
                value={selectedAccountId}
                onChange={(e) => setSelectedAccountId(e.target.value)}
                disabled={accountsLoading || settingsLoading || saving}
              >
                {accounts.map((acc) => {
                  const accId = acc._id || acc.account_id || acc.id;
                  const name = acc.account_name || "AWS Account";
                  const awsNum = acc.aws_account_id
                    ? ` (${acc.aws_account_id})`
                    : "";
                  return (
                    <option key={accId} value={accId}>
                      {name}
                      {awsNum}
                      {acc.status !== "connected" ? " [Disconnected]" : ""}
                    </option>
                  );
                })}
              </select>
            </div>
          )}

          {/* Refresh Button */}
          <button
            type="button"
            className="remediation-gov-btn-refresh"
            onClick={() => loadSettingsForAccount(selectedAccountId)}
            disabled={settingsLoading || saving || !selectedAccountId}
            title="Refresh remediation governance settings from backend"
          >
            <RefreshCw
              size={13}
              className={settingsLoading ? "animate-spin" : ""}
            />
            {settingsLoading ? "Loading..." : "Refresh"}
          </button>
        </div>
      </div>

      {/* ----------------------------------------------------
          POLICY & SAFEGUARD DISCLOSURE CALLOUT (Requirement 9 & 10)
          ----------------------------------------------------- */}
      <div className="remediation-gov-disclosure-box">
        <div className="remediation-gov-disclosure-icon">
          <Info size={18} />
        </div>
        <div className="remediation-gov-disclosure-content">
          <strong>Remediation Governance Policy & Execution Safeguards</strong>
          <p>
            Enabling a service permits CloudGuardAI to execute approved remediation playbooks and direct resource controls for that service on this AWS account.
          </p>
          <ul>
            <li>
              <strong>Does not grant IAM permissions:</strong> Enabling a service here does not grant or alter IAM permissions in your AWS account. Your cross-account IAM role must independently have the required AWS API permissions.
            </li>
            <li>
              <strong>Does not auto-execute actions:</strong> Enabling a service does not automatically execute remediations. Explicit approval and confirmation safeguards remain required for all executions.
            </li>
            <li>
              <strong>Fail-closed security:</strong> Any service toggle kept disabled strictly blocks mutations and AWS role assumption on both direct API calls and background executors.
            </li>
          </ul>
        </div>
      </div>

      {/* ----------------------------------------------------
          VIEWER ROLE BANNER (Requirement 8)
          ----------------------------------------------------- */}
      {!roleLoading && !isOwnerOrAdmin && (
        <div className="remediation-gov-viewer-banner" role="alert">
          <Lock size={16} />
          <div>
            <strong>Read-Only Access (Viewer Role):</strong>
            <span>
              {" "}You are viewing current remediation governance policies. Functional controls to enable or disable service toggles are restricted to Organization Owners and Admins.
            </span>
          </div>
        </div>
      )}

      {/* ----------------------------------------------------
          ACCOUNT DISCONNECTED WARNING
          ----------------------------------------------------- */}
      {isDisconnected && (
        <div className="remediation-gov-alert-banner alert-warning" role="alert">
          <AlertTriangle size={16} />
          <div>
            <strong>AWS Account Disconnected:</strong>
            <span>
              {" "}This AWS account is currently disconnected. Remediation execution and settings updates are locked until the account is reconnected.
            </span>
          </div>
        </div>
      )}

      {/* ----------------------------------------------------
          FEEDBACK ALERTS (SUCCESS & ERROR)
          ----------------------------------------------------- */}
      {saveSuccess && (
        <div className="remediation-gov-alert-banner alert-success" role="status">
          <Check size={16} />
          <span>{saveSuccess}</span>
          <button
            type="button"
            className="remediation-gov-alert-dismiss"
            onClick={() => setSaveSuccess("")}
            aria-label="Dismiss alert"
          >
            ×
          </button>
        </div>
      )}

      {saveError && (
        <div className="remediation-gov-alert-banner alert-error" role="alert">
          <ShieldAlert size={16} />
          <span>{saveError}</span>
          <button
            type="button"
            className="remediation-gov-alert-dismiss"
            onClick={() => setSaveError("")}
            aria-label="Dismiss alert"
          >
            ×
          </button>
        </div>
      )}

      {settingsError && (
        <div className="remediation-gov-alert-banner alert-error" role="alert">
          <AlertTriangle size={16} />
          <span>{settingsError}</span>
          <button
            type="button"
            className="remediation-gov-alert-dismiss"
            onClick={() => setSettingsError("")}
            aria-label="Dismiss alert"
          >
            ×
          </button>
        </div>
      )}

      {/* ----------------------------------------------------
          ZERO-STATE: NO CONNECTED ACCOUNTS
          ----------------------------------------------------- */}
      {!accountsLoading && accounts.length === 0 && (
        <div className="remediation-gov-empty-state">
          <HardDrive size={36} className="remediation-gov-empty-icon" />
          <h3>No Connected AWS Accounts</h3>
          <p>
            Connect an AWS account to CloudGuardAI to configure and enforce per-service remediation governance policies.
          </p>
        </div>
      )}

      {/* ----------------------------------------------------
          LOADING STATE SKELETON
          ----------------------------------------------------- */}
      {(accountsLoading || (settingsLoading && !currentAccount)) && (
        <div className="remediation-gov-loading-state">
          <div className="remediation-gov-spinner" />
          <span>Loading remediation governance configuration...</span>
        </div>
      )}

      {/* ----------------------------------------------------
          SERVICES GRID (Requirement 2 & 3)
          ----------------------------------------------------- */}
      {accounts.length > 0 && !accountsLoading && (
        <>
          <div className="remediation-gov-status-bar">
            <div className="remediation-gov-status-left">
              <span className="remediation-gov-status-pill">
                Account: <strong>{currentAccount?.account_name || "AWS Account"}</strong>
                {currentAccount?.aws_account_id ? ` (${currentAccount.aws_account_id})` : ""}
              </span>
              <span className="remediation-gov-status-pill">
                Active Policies: <strong>{enabledCount} of 6 Enabled</strong>
              </span>
              <span className="remediation-gov-status-pill">
                Storage: <strong>{existsInDb ? "Persisted in DB" : "Default Policy (Disabled)"}</strong>
              </span>
            </div>

            {lastUpdated && (
              <span className="remediation-gov-status-updated">
                Last modified: {formatDate(lastUpdated)}
                {updatedBy ? ` by ${updatedBy}` : ""}
              </span>
            )}
          </div>

          <div className="remediation-gov-grid">
            {REMEDIATION_SERVICES.map((svc) => {
              const IconComponent = svc.icon;
              const isEnabled = Boolean(settings[svc.key]);
              const isSaved = Boolean(savedSettings[svc.key]);
              const isPendingChange = isEnabled !== isSaved;
              const toggleId = `remediation-toggle-${svc.key}`;

              return (
                <div
                  key={svc.key}
                  className={`remediation-service-card ${
                    isEnabled ? "service-enabled" : "service-disabled"
                  } ${isPendingChange ? "service-pending" : ""}`}
                >
                  <div className="remediation-service-card-top">
                    <div
                      className="remediation-service-icon-box"
                      style={{
                        backgroundColor: isEnabled
                          ? `${svc.color}22`
                          : "rgba(255, 255, 255, 0.04)",
                        color: isEnabled ? svc.color : "#94a3b8",
                        border: `1px solid ${isEnabled ? `${svc.color}44` : "transparent"}`,
                      }}
                    >
                      <IconComponent size={20} />
                    </div>

                    <div className="remediation-service-title-wrap">
                      <div className="remediation-service-name-row">
                        <h3 className="remediation-service-name">
                          {svc.name}
                        </h3>
                        <span className="remediation-service-key-tag">
                          {svc.key}
                        </span>
                      </div>
                      <span
                        className={`remediation-service-badge ${
                          isEnabled ? "badge-permitted" : "badge-blocked"
                        }`}
                      >
                        {isEnabled ? "Permitted" : "Disabled (Blocked)"}
                      </span>
                    </div>

                    {/* Enable/Disable Toggle Switch */}
                    <div className="remediation-toggle-wrapper">
                      <label
                        htmlFor={toggleId}
                        className={`remediation-toggle-switch ${
                          !isOwnerOrAdmin || saving || settingsLoading || isDisconnected
                            ? "disabled"
                            : ""
                        }`}
                        title={
                          !isOwnerOrAdmin
                            ? "Only Organization Owners and Admins can toggle remediation settings"
                            : isDisconnected
                            ? "Account is disconnected"
                            : `${isEnabled ? "Disable" : "Enable"} ${svc.name} remediation`
                        }
                      >
                        <input
                          id={toggleId}
                          type="checkbox"
                          checked={isEnabled}
                          onChange={(e) => handleToggle(svc.key, e.target.checked)}
                          disabled={
                            !isOwnerOrAdmin || saving || settingsLoading || isDisconnected
                          }
                          aria-label={`Toggle remediation for ${svc.name}`}
                        />
                        <span className="remediation-toggle-slider" />
                      </label>
                    </div>
                  </div>

                  <p className="remediation-service-description">
                    {svc.description}
                  </p>

                  <div className="remediation-service-actions-list">
                    <span className="remediation-service-actions-label">
                      Governed Actions:
                    </span>
                    <div className="remediation-service-tags-wrap">
                      {svc.actions.map((act) => (
                        <span key={act} className="remediation-service-action-pill">
                          {act}
                        </span>
                      ))}
                    </div>
                  </div>

                  {isPendingChange && (
                    <div className="remediation-service-pending-badge">
                      Unsaved: Will be {isEnabled ? "Enabled" : "Disabled"}
                    </div>
                  )}
                </div>
              );
            })}
          </div>

          {/* ----------------------------------------------------
              CARD FOOTER & SAVE CONTROLS (Requirement 5)
              ----------------------------------------------------- */}
          {isOwnerOrAdmin && (
            <div className="remediation-gov-footer">
              <div className="remediation-gov-footer-info">
                {hasChanges ? (
                  <span className="remediation-gov-dirty-badge">
                    ● You have unsaved policy changes for this account.
                  </span>
                ) : (
                  <span className="remediation-gov-synced-badge">
                    ✓ All service governance policies are synced with the server.
                  </span>
                )}
              </div>

              <div className="remediation-gov-footer-actions">
                {hasChanges && (
                  <button
                    type="button"
                    className="remediation-gov-btn-reset"
                    onClick={handleReset}
                    disabled={saving || settingsLoading}
                  >
                    Discard Changes
                  </button>
                )}

                <button
                  type="button"
                  className="remediation-gov-btn-save"
                  onClick={handleSave}
                  disabled={!hasChanges || saving || settingsLoading || isDisconnected}
                >
                  {saving ? (
                    <>
                      <div className="remediation-gov-btn-spinner" />
                      Saving Policy...
                    </>
                  ) : (
                    <>
                      <Check size={15} />
                      Save Governance Changes
                    </>
                  )}
                </button>
              </div>
            </div>
          )}
        </>
      )}
    </section>
  );
}
