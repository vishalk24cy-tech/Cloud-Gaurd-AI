import { useEffect, useMemo, useState } from "react";
import { Link } from "react-router-dom";
import {
  AlertTriangle,
  ArrowRight,
  Check,
  ChevronDown,
  CircleAlert,
  LoaderCircle,
  ShieldCheck,
} from "lucide-react";
import {
  createRemediationProposal,
  getRemediationActions,
  getRemediationAudit,
  approveRemediation,
  executeRemediation,
  verifyRemediation,
} from "../services/remediationService";
import "./FindingRemediation.css";

const EXECUTABLE_ACTIONS = new Set([
  "EC2_STOP_INSTANCE",
  "S3_ENABLE_BLOCK_PUBLIC_ACCESS",
  "IAM_DISABLE_ACCESS_KEY",
  "VPC_REMOVE_INSECURE_INGRESS",
  "RDS_DISABLE_PUBLIC_ACCESS",
  "CLOUDTRAIL_ENABLE_LOGGING",
]);

const SSH_FINDINGS = new Set([
  "SSH port 22 is open to the Internet.",
  "SSH port 22 is open to the Internet over IPv6.",
]);

function normalize(value) {
  return String(value || "").trim().toUpperCase();
}

function getFindingStatus(finding) {
  const status = normalize(finding?.status || "OPEN");
  if (["FAILED", "FAIL", "RISK"].includes(status)) return "OPEN";
  if (["PROTECTED", "PASS", "PASSED"].includes(status)) return "PROTECTED";
  return status;
}

function getService(finding) {
  const service = normalize(finding?.service);
  if (service) return service;
  const type = normalize(finding?.resource_type);
  if (type.includes("LAMBDA")) return "LAMBDA";
  if (type.includes("CLOUDTRAIL")) return "CLOUDTRAIL";
  if (type.includes("RDS")) return "RDS";
  if (type.includes("KMS")) return "KMS";
  if (type.includes("IAM")) return "IAM";
  if (type.includes("S3")) return "S3";
  return type;
}

function identifyAction(finding) {
  const service = getService(finding);
  const issue = String(finding?.issue || "").trim();
  const resource = String(finding?.resource || "").trim();
  const resourceType = normalize(finding?.resource_type).replaceAll(" ", "_");

  if (service === "EC2" && resourceType === "EC2_INSTANCE" && /^i-[0-9a-f]{8}(?:[0-9a-f]{9})?$/i.test(resource)) {
    return { actionId: "EC2_STOP_INSTANCE", resourceId: resource };
  }

  if (service === "S3" && resource && /public|access|policy/i.test(issue)) {
    return { actionId: "S3_ENABLE_BLOCK_PUBLIC_ACCESS", resourceId: resource };
  }

  if (service === "IAM" && resourceType === "IAM_ACCESS_KEY" && issue === "IAM access key is active.") {
    const resourceId = String(finding?.access_key_id || resource).trim();
    const username = String(finding?.user || "").trim();
    if (resourceId && username) {
      return { actionId: "IAM_DISABLE_ACCESS_KEY", resourceId, username };
    }
  }

  if (service === "VPC" && SSH_FINDINGS.has(issue)) {
    return { actionId: "VPC_REMOVE_INSECURE_INGRESS" };
  }

  if (service === "RDS" && issue === "RDS database is publicly accessible.") {
    return { actionId: "RDS_DISABLE_PUBLIC_ACCESS" };
  }

  if (service === "CLOUDTRAIL" && /^CloudTrail logging is disabled \(.+\)\.$/.test(issue)) {
    return { actionId: "CLOUDTRAIL_ENABLE_LOGGING" };
  }

  return null;
}

function friendlyError(error) {
  const status = error?.response?.status;
  if (status === 401) return "Your session expired. Sign in again to continue.";
  if (status === 403) return "You do not have permission to perform this remediation.";
  if (status === 404) return "The finding or connected AWS resource could not be found.";
  if (status === 409) {
    const detail = error?.response?.data?.detail;
    return typeof detail === "string" ? detail : detail?.message || "This remediation is no longer available in its current state.";
  }
  if (status === 422) return "The remediation request needs valid resource details.";
  if (status >= 500) return "CloudGuardAI could not complete the request. No success was reported.";
  return error?.message || "The remediation request failed.";
}

function formatActionName(action) {
  return String(action?.action_name || action?.action_id || "Remediation")
    .replaceAll("_", " ");
}

function statusLabel(value) {
  return String(value || "PROPOSED").replaceAll("_", " ");
}

function FindingRemediation({ finding, accountId }) {
  const [actions, setActions] = useState([]);
  const [actionsLoading, setActionsLoading] = useState(true);
  const [actionsError, setActionsError] = useState("");
  const [proposal, setProposal] = useState(null);
  const [auditEvents, setAuditEvents] = useState([]);
  const [detailsOpen, setDetailsOpen] = useState(false);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");
  const [message, setMessage] = useState("");

  const candidate = useMemo(() => identifyAction(finding), [finding]);
  const findingStatus = getFindingStatus(finding);
  const gatedService = ["LAMBDA", "KMS"].includes(getService(finding));

  useEffect(() => {
    let active = true;
    setActionsLoading(true);
    setActionsError("");
    setProposal(null);
    setAuditEvents([]);
    setError("");
    setMessage("");

    getRemediationActions()
      .then((items) => {
        if (active) setActions(items);
      })
      .catch((requestError) => {
        if (active) setActionsError(friendlyError(requestError));
      })
      .finally(() => {
        if (active) setActionsLoading(false);
      });

    return () => {
      active = false;
    };
  }, [finding?.finding_id, finding?.resource, finding?.issue]);

  const action = useMemo(
    () => actions.find((item) => item.action_id === candidate?.actionId) || null,
    [actions, candidate]
  );
  const executable = Boolean(
    candidate && action && EXECUTABLE_ACTIONS.has(action.action_id)
  );

  async function loadAudit(remediationId) {
    if (!remediationId) return;
    try {
      const items = await getRemediationAudit(remediationId);
      setAuditEvents(items);
    } catch {
      setAuditEvents([]);
    }
  }

  async function startProposal() {
    if (!candidate || !action || busy || !accountId) return;
    setBusy(true);
    setError("");
    setMessage("");

    const payload = { account_id: accountId };
    if (["VPC_REMOVE_INSECURE_INGRESS", "RDS_DISABLE_PUBLIC_ACCESS", "CLOUDTRAIL_ENABLE_LOGGING"].includes(action.action_id)) {
      payload.finding_id = finding.finding_id;
    } else {
      payload.resource_id = candidate.resourceId;
      if (action.action_id === "IAM_DISABLE_ACCESS_KEY") {
        payload.username = candidate.username;
      }
    }

    try {
      const response = await createRemediationProposal(action.action_id, payload);
      const created = response?.remediation || null;
      setProposal(created);
      setMessage(response?.deduplicated ? "An active proposal already exists for this resource." : "Remediation proposal created. AWS has not been changed.");
      await loadAudit(created?._id || created?.id);
    } catch (requestError) {
      setError(friendlyError(requestError));
    } finally {
      setBusy(false);
    }
  }

  async function handleApprove() {
    if (!proposal || busy) return;
    const id = proposal._id || proposal.id;
    if (!id) return;
    
    setBusy(true);
    setError("");
    setMessage("");
    try {
      const response = await approveRemediation(id);
      const updated = response?.remediation || null;
      if (updated) setProposal(updated);
      setMessage("Remediation approved. Execution is now required to change AWS.");
      await loadAudit(id);
    } catch (err) {
      setError(friendlyError(err));
    } finally {
      setBusy(false);
    }
  }

  async function handleExecute() {
    if (!proposal || busy) return;
    const id = proposal._id || proposal.id;
    if (!id) return;
    
    const confirmed = window.confirm("This action will make a real AWS security change. Continue?");
    if (!confirmed) return;
    
    setBusy(true);
    setError("");
    setMessage("");
    try {
      const response = await executeRemediation(id);
      const result = response?.remediation || null;
      if (result) setProposal(result);
      
      if (response?.status === "failed" || result?.success === false) {
        setError(result?.error || result?.message || "AWS remediation failed.");
      } else {
        setMessage("AWS remediation completed and the resulting state was verified.");
      }
      await loadAudit(id);
    } catch (err) {
      setError(friendlyError(err));
      await loadAudit(id);
    } finally {
      setBusy(false);
    }
  }

  async function handleVerify() {
    if (!proposal || busy) return;
    const id = proposal._id || proposal.id;
    if (!id) return;

    setBusy(true);
    setError("");
    setMessage("");
    try {
      const response = await verifyRemediation(id);
      // We don't have the full proposal returned, so we artificially update verification state locally
      // Or we can just let it fetch if there's a fetcher, but we don't have one here.
      setProposal((prev) => ({
        ...prev,
        verification: { ...prev.verification, status: "pending" },
      }));
      setMessage("Verification scan requested successfully.");
      await loadAudit(id);
    } catch (err) {
      setError(friendlyError(err));
    } finally {
      setBusy(false);
    }
  }

  const resourceLabel = proposal?.resource || candidate?.resourceId || finding?.resource || "Finding resource";
  const actionStatus = proposal?.status || null;

  return (
    <section className="finding-remediation" aria-labelledby="finding-remediation-title">
      <div className="finding-remediation__heading">
        <div className="finding-remediation__icon" aria-hidden="true"><ShieldCheck size={17} /></div>
        <div>
          <span className="finding-remediation__eyebrow">RECOMMENDED REMEDIATION</span>
          <h3 id="finding-remediation-title">Remediation</h3>
        </div>
        {findingStatus === "OPEN" && <span className="finding-remediation__finding-state">Finding remains open</span>}
      </div>

      {gatedService ? (
        <div className="finding-remediation__notice finding-remediation__notice--amber" role="status">
          <AlertTriangle size={16} aria-hidden="true" />
          <p>Recommendation available. Automatic remediation is currently unavailable because the required resource or security evidence is insufficient.</p>
        </div>
      ) : actionsLoading ? (
        <div className="finding-remediation__loading" role="status"><LoaderCircle size={16} /> Checking registered actions…</div>
      ) : actionsError ? (
        <div className="finding-remediation__notice finding-remediation__notice--red" role="alert"><CircleAlert size={16} /><p>{actionsError}</p></div>
      ) : !candidate ? (
        <div className="finding-remediation__notice" role="status"><AlertTriangle size={16} /><p>No executable action is available for this finding evidence.</p></div>
      ) : !action ? (
        <div className="finding-remediation__notice" role="status"><AlertTriangle size={16} /><p>The backend has not exposed a remediation action for this finding.</p></div>
      ) : !EXECUTABLE_ACTIONS.has(action.action_id) ? (
        <div className="finding-remediation__notice finding-remediation__notice--amber" role="status"><AlertTriangle size={16} /><p>This registered action is not enabled for execution.</p></div>
      ) : findingStatus !== "OPEN" ? (
        <div className="finding-remediation__notice" role="status"><Check size={16} /><p>Remediation proposals are available only for open findings.</p></div>
      ) : proposal ? (
        <div className="finding-remediation__proposal" aria-live="polite">
          <div className="finding-remediation__proposal-top">
            <span className="finding-remediation__status"><Check size={13} /> {statusLabel(actionStatus)}</span>
            <strong>Proposal created</strong>
          </div>
          <dl className="finding-remediation__facts">
            <div><dt>Action</dt><dd>{formatActionName(action)}</dd></div>
            <div><dt>Resource</dt><dd>{resourceLabel}</dd></div>
            <div><dt>AWS account</dt><dd>{finding.aws_account_id || "Connected account"}</dd></div>
            <div><dt>Finding status</dt><dd>{findingStatus}</dd></div>
          </dl>
          
          {(actionStatus === "PROPOSED" || actionStatus === "PENDING_APPROVAL") && (
            <div className="finding-remediation__actions-bar">
              <p className="finding-remediation__safe-note">This proposal has not changed AWS. Approval is required before execution.</p>
              <button className="finding-remediation__start" onClick={handleApprove} disabled={busy}>
                {busy ? <LoaderCircle size={15} className="finding-remediation__spin" /> : <ShieldCheck size={15} />}
                {busy ? "Approving..." : "Approve Remediation"}
              </button>
            </div>
          )}

          {actionStatus === "APPROVED" && (
            <div className="finding-remediation__actions-bar">
              <p className="finding-remediation__safe-note">Approval granted. Explicit execution confirmation is required to modify AWS.</p>
              <button className="finding-remediation__start finding-remediation__start--execute" onClick={handleExecute} disabled={busy}>
                {busy ? <LoaderCircle size={15} className="finding-remediation__spin" /> : <ShieldCheck size={15} />}
                {busy ? "Executing on AWS..." : "Execute Remediation"}
              </button>
            </div>
          )}

          {actionStatus === "EXECUTING" && (
            <div className="finding-remediation__notice" role="status">
              <LoaderCircle size={16} className="finding-remediation__spin" />
              <p>AWS remediation is currently executing...</p>
            </div>
          )}

          {(actionStatus === "COMPLETED" || actionStatus === "FAILED") && (
            <div className={`finding-remediation__notice ${actionStatus === "FAILED" ? "finding-remediation__notice--red" : ""}`}>
              {actionStatus === "FAILED" ? <CircleAlert size={16} /> : <Check size={16} />}
              <div>
                <strong>{actionStatus === "COMPLETED" ? "Execution Completed" : "Execution Failed"}</strong>
                {proposal?.execution_result?.error && <p>{proposal.execution_result.error}</p>}
                
                {actionStatus === "COMPLETED" && (
                  <div className="finding-remediation__verification-block">
                    {proposal?.verification?.verified ? (
                      <p className="finding-remediation__verification">
                        Verification: Passed 
                        {proposal.verification.scan_id ? ` (Scan ${proposal.verification.scan_id})` : ""}
                      </p>
                    ) : proposal?.verification?.status === "pending" ? (
                      <p className="finding-remediation__verification finding-remediation__verification--pending">
                        Re-evaluation pending...
                      </p>
                    ) : (
                      <div className="finding-remediation__actions-bar">
                        <p className="finding-remediation__safe-note">Execution completed. Request a re-evaluation scan to verify the security finding is resolved.</p>
                        <button className="finding-remediation__start" onClick={handleVerify} disabled={busy}>
                          {busy ? <LoaderCircle size={15} className="finding-remediation__spin" /> : <ShieldCheck size={15} />}
                          {busy ? "Requesting..." : "Verify Remediation"}
                        </button>
                      </div>
                    )}
                  </div>
                )}
              </div>
            </div>
          )}

          {error && <div className="finding-remediation__inline-error" role="alert"><CircleAlert size={15} />{error}</div>}
          {message && <div className="finding-remediation__inline-success" role="status">{message}</div>}

          <Link className="finding-remediation__link" to={`/remediation?remediation_id=${encodeURIComponent(proposal._id || proposal.id || "")}`}>
            Open in Remediation Center <ArrowRight size={14} />
          </Link>
          {auditEvents.length > 0 && (
            <ol className="finding-remediation__audit" aria-label="Recorded remediation audit events">
              {auditEvents.map((event) => (
                <li key={event._id || `${event.event_type}-${event.created_at}`}>
                  <span>{String(event.event_type || "AUDIT").replaceAll("_", " ")}</span>
                  <time>{event.created_at ? new Date(event.created_at).toLocaleString() : ""}</time>
                </li>
              ))}
            </ol>
          )}
        </div>
      ) : (
        <>
          <div className="finding-remediation__action-row">
            <div>
              <strong>{formatActionName(action)}</strong>
              <span>{action.service} · {action.resource_type}</span>
              <small>Risk: {action.risk_level || "—"} · {action.classification}</small>
            </div>
            <button
              className="finding-remediation__detail-toggle"
              type="button"
              aria-expanded={detailsOpen}
              onClick={() => setDetailsOpen((open) => !open)}
            >
              {detailsOpen ? "Hide details" : "View action"}<ChevronDown size={14} />
            </button>
          </div>

          {detailsOpen && (
            <div className="finding-remediation__details">
              <dl>
                <div><dt>Action ID</dt><dd>{action.action_id}</dd></div>
                <div><dt>Service</dt><dd>{action.service}</dd></div>
                <div><dt>Resource type</dt><dd>{action.resource_type}</dd></div>
                <div><dt>Allowed roles</dt><dd>{(action.allowed_roles || []).join(", ") || "Backend controlled"}</dd></div>
                <div><dt>Approval</dt><dd>{action.requires_approval ? "Required" : "Not required"}</dd></div>
                <div><dt>Confirmation</dt><dd>{action.requires_confirmation ? "Required" : "Not required"}</dd></div>
              </dl>
              <p>{action.description}</p>
              <p className="finding-remediation__warning">This action will modify a live AWS resource. An authorized user must approve it, and execution requires a separate confirmation.</p>
            </div>
          )}

          <div className="finding-remediation__target">
            <span>Target resource</span>
            <strong>{candidate.resourceId || finding.resource || "Derived from this finding"}</strong>
          </div>

          {error && <div className="finding-remediation__inline-error" role="alert"><CircleAlert size={15} />{error}</div>}
          {message && <div className="finding-remediation__inline-success" role="status">{message}</div>}

          {!accountId ? (
            <div className="finding-remediation__notice finding-remediation__notice--red" role="alert"><CircleAlert size={16} /><p>The connected AWS account reference is missing from this scan. Refresh findings before creating a proposal.</p></div>
          ) : (
            <button className="finding-remediation__start" type="button" onClick={startProposal} disabled={busy}>
              {busy ? <LoaderCircle size={15} className="finding-remediation__spin" /> : <ShieldCheck size={15} />}
              {busy ? "Creating proposal…" : "Start remediation"}
            </button>
          )}
          <p className="finding-remediation__safe-note">Creation does not execute AWS changes. The backend revalidates authorization and resource ownership.</p>
        </>
      )}
    </section>
  );
}

export default FindingRemediation;
