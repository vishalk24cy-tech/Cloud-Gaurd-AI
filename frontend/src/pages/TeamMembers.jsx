import React, { useEffect, useState } from "react";
import { Check, Crown, Eye, MailPlus, RefreshCw, Search, ShieldCheck, Users, X } from "lucide-react";
import api from "../services/api";
import "./TeamMembers.css";

function TeamMembers() {
  const [organizationId, setOrganizationId] = useState("");
  const [members, setMembers] = useState([]);
  const [totalMembers, setTotalMembers] = useState(0);
  const [memberLimit, setMemberLimit] = useState(0);

  const [loading, setLoading] = useState(true);
  const [refreshing, setRefreshing] = useState(false);

  const [showInvite, setShowInvite] = useState(false);

  const [inviteEmail, setInviteEmail] = useState("");
  const [inviteRole, setInviteRole] = useState("viewer");

  const [inviteLoading, setInviteLoading] = useState(false);
  const [actionLoading, setActionLoading] = useState("");

  const [error, setError] = useState("");
  const [success, setSuccess] = useState("");

  // ============================================================
  // GET ORGANIZATION ID
  // ============================================================

  const getOrganizationId = () => {
    try {
      const user = JSON.parse(
        localStorage.getItem("user") || "{}"
      );

      return String(
        user.organization ||
        user.organization_id ||
        ""
      ).trim();

    } catch (error) {
      console.error(
        "[TEAM MEMBERS USER PARSE ERROR]",
        error
      );

      return "";
    }
  };


  // ============================================================
  // LOAD TEAM MEMBERS
  // ============================================================

  const loadMembers = async (showLoader = true) => {

    if (showLoader) {
      setLoading(true);
    } else {
      setRefreshing(true);
    }

    setError("");

    try {

      const orgId =
        organizationId ||
        getOrganizationId();

      if (!orgId) {

        throw new Error(
          "Organization context is missing."
        );

      }

      setOrganizationId(orgId);


      // --------------------------------------------------------
      // MEMBERS
      // --------------------------------------------------------

      const membersResponse =
        await api.get(
          `/organizations/${orgId}/members`
        );


      const memberData =
        membersResponse.data || {};


      const memberList =
        Array.isArray(
          memberData.members
        )
          ? memberData.members
          : [];


      setMembers(memberList);


      setTotalMembers(
        Number(
          memberData.total_members ??
          memberList.length
        )
      );


      // --------------------------------------------------------
      // USAGE / QUOTA
      // --------------------------------------------------------

      try {

        const usageResponse =
          await api.get(
            `/organizations/${orgId}/usage`
          );


        const usage =
          usageResponse.data?.usage || {};

        const quotas =
          usage.quotas || {};

        const teamQuota =
          quotas.team_members || {};


        setMemberLimit(
          teamQuota.unlimited
            ? -1
            : Number(
                teamQuota.limit || 0
              )
        );

      } catch (quotaError) {

        console.warn(
          "[TEAM MEMBERS QUOTA LOAD ERROR]",
          quotaError
        );

      }

    } catch (err) {

      console.error(
        "[TEAM MEMBERS LOAD ERROR]",
        err
      );

      setError(
        err.response?.data?.detail ||
        err.message ||
        "Failed to load team members."
      );

    } finally {

      setLoading(false);
      setRefreshing(false);

    }

  };


  // ============================================================
  // INITIAL LOAD
  // ============================================================

  useEffect(() => {

    const orgId =
      getOrganizationId();

    if (orgId) {

      setOrganizationId(
        orgId
      );

      loadMembers(true);

    } else {

      setLoading(false);

      setError(
        "Organization context is missing."
      );

    }

  }, []);


  // ============================================================
  // INVITE MEMBER
  // ============================================================

  const inviteMember = async (event) => {

    event.preventDefault();

    setError("");
    setSuccess("");

    const email =
      inviteEmail.trim();

    if (!email) {

      setError(
        "Please enter the member email address."
      );

      return;

    }


    if (!email.includes("@")) {

      setError(
        "Please enter a valid email address."
      );

      return;

    }


    if (
      memberLimit !== -1 &&
      memberLimit > 0 &&
      totalMembers >= memberLimit
    ) {

      setError(
        `Team member quota reached. Current usage: ${totalMembers}, limit: ${memberLimit}.`
      );

      return;

    }


    setInviteLoading(true);

    try {

      const response =
        await api.post(
          `/organizations/${organizationId}/invitations`,
          {
            email,
            role: inviteRole
          }
        );


      setInviteEmail("");
      setInviteRole("viewer");

      setShowInvite(false);

      setSuccess(
        response.data?.message ||
        "Invitation created successfully."
      );


      await loadMembers(false);

    } catch (err) {

      console.error(
        "[TEAM MEMBER INVITE ERROR]",
        err
      );

      setError(
        err.response?.data?.detail ||
        "Failed to invite team member."
      );

    } finally {

      setInviteLoading(false);

    }

  };


  // ============================================================
  // CHANGE MEMBER ROLE
  // ============================================================

  const changeRole = async (
    member,
    newRole
  ) => {

    if (
      !member?.user_id ||
      !newRole
    ) {
      return;
    }


    if (
      member.role === newRole
    ) {
      return;
    }


    setError("");
    setSuccess("");

    setActionLoading(
      `role-${member.user_id}`
    );


    try {

      const response =
        await api.patch(
          `/organizations/${organizationId}/members/${member.user_id}/role`,
          {
            role: newRole
          }
        );


      setSuccess(
        response.data?.message ||
        "Member role updated successfully."
      );


      await loadMembers(false);

    } catch (err) {

      console.error(
        "[TEAM MEMBER ROLE ERROR]",
        err
      );

      setError(
        err.response?.data?.detail ||
        "Failed to update member role."
      );

    } finally {

      setActionLoading("");

    }

  };


  // ============================================================
  // REMOVE MEMBER
  // ============================================================

  const removeMember = async (
    member
  ) => {

    if (
      !member?.user_id
    ) {
      return;
    }


    if (
      member.role === "owner"
    ) {

      setError(
        "The organization owner cannot be removed."
      );

      return;

    }


    const confirmed =
      window.confirm(
        `Remove ${member.name || member.email} from this organization?`
      );


    if (!confirmed) {
      return;
    }


    setError("");
    setSuccess("");

    setActionLoading(
      `remove-${member.user_id}`
    );


    try {

      const response =
        await api.delete(
          `/organizations/${organizationId}/members/${member.user_id}`
        );


      setSuccess(
        response.data?.message ||
        "Member removed successfully."
      );


      await loadMembers(false);

    } catch (err) {

      console.error(
        "[TEAM MEMBER REMOVE ERROR]",
        err
      );

      setError(
        err.response?.data?.detail ||
        "Failed to remove team member."
      );

    } finally {

      setActionLoading("");

    }

  };


  // ============================================================
  // CLOSE INVITE MODAL
  // ============================================================

  const closeInvite = () => {

    if (inviteLoading) {
      return;
    }

    setShowInvite(false);
    setInviteEmail("");
    setInviteRole("viewer");
    setError("");

  };


  // ============================================================
  // LOADING
  // ============================================================

  if (loading) {

    return (

      <div style={styles.page}>

        <div style={styles.loading}>

          <div
            style={styles.spinner}
          />

          <h2
            style={styles.loadingTitle}
          >
            Loading Team Members
          </h2>

          <p
            style={styles.loadingText}
          >
            Loading organization members...
          </p>

        </div>

      </div>

    );

  }


  // ============================================================
  // PAGE
  // ============================================================

  return (

    <div className="team-members-phase5" style={styles.page}>

      {/* ======================================================
          HEADER
          ====================================================== */}

      <div style={styles.header}>

        <div>

          <p style={styles.eyebrow}>
            SAAS MANAGEMENT
          </p>

          <h1 style={styles.title}>
            Team Members
          </h1>

          <p style={styles.subtitle}>
            Manage organization members, roles and
            access permissions.
          </p>

        </div>


        <div
          style={styles.headerActions}
        >

          <button
            type="button"
            onClick={() =>
              loadMembers(false)
            }
            disabled={refreshing}
            style={styles.refreshButton}
          >

            <RefreshCw size={14} /> {refreshing
              ? "Refreshing..."
              : "↻ Refresh"}

          </button>


          <button
            type="button"
            onClick={() => {
              setError("");
              setSuccess("");
              setShowInvite(true);
            }}
            style={styles.inviteButton}
          >

            <MailPlus size={15} /> Invite Member

          </button>

        </div>

      </div>


      {/* ======================================================
          ALERTS
          ====================================================== */}

      {success && (

        <div
          style={styles.successAlert}
        >

          <span
            style={styles.alertIcon}
          >
            <Check size={15} />
          </span>

          <span>
            {success}
          </span>

        </div>

      )}


      {error && (

        <div
          style={styles.errorAlert}
        >

          <span
            style={styles.errorAlertIcon}
          >
            !
          </span>

          <span>
            {error}
          </span>

        </div>

      )}


      {/* ======================================================
          ORGANIZATION SUMMARY
          ====================================================== */}

      <section
        style={styles.summaryCard}
      >

        <div>

          <p
            style={styles.sectionLabel}
          >
            ORGANIZATION
          </p>

          <h2
            style={styles.sectionTitle}
          >
            Team Access
          </h2>

          <p
            style={styles.sectionDescription}
          >
            Active members with access to this
            CloudGuardAI organization.
          </p>

        </div>


        <div
          style={styles.quotaBox}
        >

          <span
            style={styles.quotaLabel}
          >
            TEAM MEMBERS
          </span>

          <div
            style={styles.quotaNumbers}
          >

            <strong
              style={styles.quotaUsed}
            >
              {totalMembers}
            </strong>

            <span
              style={styles.quotaSlash}
            >
              /
            </span>

            <span
              style={styles.quotaLimit}
            >

              {memberLimit === -1
                ? "Unlimited"
                : memberLimit || "—"}

            </span>

          </div>

          <span
            style={styles.quotaStatus}
          >

            {memberLimit === -1
              ? "Unlimited members"
              : memberLimit > 0
                ? `${Math.max(
                    memberLimit -
                      totalMembers,
                    0
                  )} seats remaining`
                : "Quota unavailable"}

          </span>

        </div>

      </section>


      {/* ======================================================
          MEMBERS TABLE
          ====================================================== */}

      <section
        style={styles.card}
      >

        <div
          style={styles.cardHeader}
        >

          <div>

            <p
              style={styles.sectionLabel}
            >
              MEMBERS
            </p>

            <h2
              style={styles.sectionTitle}
            >
              Organization Members
            </h2>

          </div>

          <span
            style={styles.memberCountBadge}
          >
            {totalMembers}{" "}
            {totalMembers === 1
              ? "Member"
              : "Members"}
          </span>

        </div>


        {members.length === 0 ? (

          <div
            style={styles.emptyState}
          >

            <div
              style={styles.emptyIcon}
            >
              <Users size={24} />
            </div>

            <h3
              style={styles.emptyTitle}
            >
              No active members
            </h3>

            <p
              style={styles.emptyText}
            >
              Invite your first team member
              to collaborate securely.
            </p>

            <button
              type="button"
              onClick={() =>
                setShowInvite(true)
              }
              style={styles.inviteButton}
            >
              + Invite Member
            </button>

          </div>

        ) : (

          <div
            style={styles.tableWrapper}
          >

            <table
              style={styles.table}
            >

              <thead>

                <tr>

                  <th
                    style={styles.th}
                  >
                    MEMBER
                  </th>

                  <th
                    style={styles.th}
                  >
                    ROLE
                  </th>

                  <th
                    style={styles.th}
                  >
                    STATUS
                  </th>

                  <th
                    style={styles.th}
                  >
                    JOINED
                  </th>

                  <th
                    style={{
                      ...styles.th,
                      textAlign: "right"
                    }}
                  >
                    ACTIONS
                  </th>

                </tr>

              </thead>


              <tbody>

                {members.map(
                  (member) => {

                    const roleLoading =
                      actionLoading ===
                      `role-${member.user_id}`;

                    const removeLoading =
                      actionLoading ===
                      `remove-${member.user_id}`;


                    return (

                      <tr
                        key={
                          member.user_id
                        }
                        style={styles.tr}
                      >

                        {/* MEMBER */}

                        <td
                          style={styles.td}
                        >

                          <div
                            style={
                              styles.memberCell
                            }
                          >

                            <div
                              style={
                                styles.avatar
                              }
                            >
                              {(
                                member.name ||
                                member.email ||
                                "U"
                              )
                                .charAt(0)
                                .toUpperCase()}
                            </div>


                            <div>

                              <strong
                                style={
                                  styles.memberName
                                }
                              >
                                {member.name ||
                                  "Unnamed User"}
                              </strong>

                              <span
                                style={
                                  styles.memberEmail
                                }
                              >
                                {member.email ||
                                  "No email"}
                              </span>

                            </div>

                          </div>

                        </td>


                        {/* ROLE */}

                        <td
                          style={styles.td}
                        >

                          {member.role ===
                          "owner" ? (

                            <span
                              style={
                                styles.ownerBadge
                              }
                            >
                              OWNER
                            </span>

                          ) : (

                            <select
                              value={
                                member.role ||
                                "viewer"
                              }
                              disabled={
                                roleLoading
                              }
                              onChange={(event) =>
                                changeRole(
                                  member,
                                  event.target.value
                                )
                              }
                              style={
                                styles.roleSelect
                              }
                            >

                              <option value="admin">
                                Admin
                              </option>

                              <option value="analyst">
                                Analyst
                              </option>

                              <option value="viewer">
                                Viewer
                              </option>

                            </select>

                          )}

                        </td>


                        {/* STATUS */}

                        <td
                          style={styles.td}
                        >

                          <span
                            style={
                              styles.statusBadge
                            }
                          >

                            <span
                              style={
                                styles.statusDot
                              }
                            />

                            {String(
                              member.status ||
                              "active"
                            ).toUpperCase()}

                          </span>

                        </td>


                        {/* JOINED */}

                        <td
                          style={styles.td}
                        >

                          <span
                            style={
                              styles.dateText
                            }
                          >

                            {member.joined_at
                              ? new Date(
                                  member.joined_at
                                ).toLocaleDateString()
                              : "—"}

                          </span>

                        </td>


                        {/* ACTIONS */}

                        <td
                          style={{
                            ...styles.td,
                            textAlign: "right"
                          }}
                        >

                          {member.role ===
                          "owner" ? (

                            <span
                              style={
                                styles.protectedText
                              }
                            >
                              Protected
                            </span>

                          ) : (

                            <button
                              type="button"
                              disabled={
                                removeLoading
                              }
                              onClick={() =>
                                removeMember(
                                  member
                                )
                              }
                              style={
                                styles.removeButton
                              }
                            >

                              {removeLoading
                                ? "Removing..."
                                : "Remove"}

                            </button>

                          )}

                        </td>

                      </tr>

                    );

                  }
                )}

              </tbody>

            </table>

          </div>

        )}

      </section>


      {/* ======================================================
          ROLE INFORMATION
          ====================================================== */}

      <section
        style={styles.card}
      >

        <div
          style={styles.cardHeader}
        >

          <div>

            <p
              style={styles.sectionLabel}
            >
              RBAC
            </p>

            <h2
              style={styles.sectionTitle}
            >
              Role Permissions
            </h2>

          </div>

        </div>


        <div
          style={styles.rolesGrid}
        >

          <div
            style={styles.roleBox}
          >

            <div
              style={styles.roleTitleRow}
            >

              <span
                style={styles.roleIcon}
              >
                <Crown size={16} />
              </span>

              <strong>
                Owner
              </strong>

            </div>

            <p
              style={styles.roleDescription}
            >
              Full organization control,
              including members, roles,
              subscriptions and resources.
            </p>

          </div>


          <div
            style={styles.roleBox}
          >

            <div
              style={styles.roleTitleRow}
            >

              <span
                style={styles.roleIcon}
              >
                <ShieldCheck size={16} />
              </span>

              <strong>
                Admin
              </strong>

            </div>

            <p
              style={styles.roleDescription}
            >
              Organization administration,
              member management and
              security operations.
            </p>

          </div>


          <div
            style={styles.roleBox}
          >

            <div
              style={styles.roleTitleRow}
            >

              <span
                style={styles.roleIcon}
              >
                <Search size={16} />
              </span>

              <strong>
                Analyst
              </strong>

            </div>

            <p
              style={styles.roleDescription}
            >
              Security analysis and
              investigation access without
              organization administration.
            </p>

          </div>


          <div
            style={styles.roleBox}
          >

            <div
              style={styles.roleTitleRow}
            >

              <span
                style={styles.roleIcon}
              >
                <Eye size={16} />
              </span>

              <strong>
                Viewer
              </strong>

            </div>

            <p
              style={styles.roleDescription}
            >
              Read-only access to permitted
              organization security information.
            </p>

          </div>

        </div>

      </section>


      {/* ======================================================
          INVITE MODAL
          ====================================================== */}

      {showInvite && (

        <div
          style={styles.modalOverlay}
          onMouseDown={(event) => {

            if (
              event.target ===
              event.currentTarget
            ) {
              closeInvite();
            }

          }}
        >

          <div
            style={styles.modal}
          >

            <div
              style={styles.modalHeader}
            >

              <div>

                <p
                  style={styles.sectionLabel}
                >
                  TEAM MANAGEMENT
                </p>

                <h2
                  style={styles.modalTitle}
                >
                  Invite Team Member
                </h2>

              </div>


              <button
                type="button"
                onClick={closeInvite}
                disabled={inviteLoading}
                style={
                  styles.closeButton
                }
              >
                <X size={18} />
              </button>

            </div>


            <p
              style={styles.modalDescription}
            >
              Send an invitation to add a
              member to your organization.
            </p>


            <form
              onSubmit={inviteMember}
            >

              <label
                style={styles.formLabel}
              >
                Email Address
              </label>

              <input
                type="email"
                value={inviteEmail}
                onChange={(event) =>
                  setInviteEmail(
                    event.target.value
                  )
                }
                placeholder="member@company.com"
                disabled={inviteLoading}
                autoFocus
                style={styles.input}
              />


              <label
                style={styles.formLabel}
              >
                Role
              </label>

              <select
                value={inviteRole}
                onChange={(event) =>
                  setInviteRole(
                    event.target.value
                  )
                }
                disabled={inviteLoading}
                style={styles.input}
              >

                <option value="viewer">
                  Viewer
                </option>

                <option value="analyst">
                  Analyst
                </option>

                <option value="admin">
                  Admin
                </option>

              </select>


              <div
                style={styles.inviteInfo}
              >

                <span
                  style={
                    styles.inviteInfoIcon
                  }
                >
                  ℹ
                </span>

                <span>
                  The invitation will be
                  valid for 72 hours.
                </span>

              </div>


              <div
                style={styles.modalActions}
              >

                <button
                  type="button"
                  onClick={closeInvite}
                  disabled={
                    inviteLoading
                  }
                  style={
                    styles.cancelButton
                  }
                >
                  Cancel
                </button>


                <button
                  type="submit"
                  disabled={
                    inviteLoading ||
                    !inviteEmail.trim()
                  }
                  style={
                    styles.inviteSubmitButton
                  }
                >

                  {inviteLoading
                    ? "Sending..."
                    : "Send Invitation"}

                </button>

              </div>

            </form>

          </div>

        </div>

      )}

    </div>

  );

}


// ============================================================
// STYLES
// ============================================================

const styles = {

  page: {
    minHeight: "100%",
    padding: "32px",
    boxSizing: "border-box",
    background:
      "linear-gradient(135deg, #f8fafc 0%, #eef2ff 100%)",
  },


  header: {
    display: "flex",
    justifyContent: "space-between",
    alignItems: "flex-start",
    gap: "20px",
    marginBottom: "25px",
  },


  headerActions: {
    display: "flex",
    gap: "10px",
    alignItems: "center",
  },


  eyebrow: {
    margin: "0 0 7px 0",
    fontSize: "11px",
    fontWeight: "800",
    letterSpacing: "1.5px",
    color: "#34d399",
  },


  title: {
    margin: 0,
    fontSize: "31px",
    fontWeight: "800",
    color: "#111827",
  },


  subtitle: {
    margin: "8px 0 0 0",
    fontSize: "14px",
    color: "#64748b",
  },


  refreshButton: {
    padding: "10px 15px",
    borderRadius: "10px",
    border: "1px solid #cbd5e1",
    background: "#ffffff",
    color: "#334155",
    fontSize: "13px",
    fontWeight: "700",
    cursor: "pointer",
  },


  inviteButton: {
    padding: "11px 17px",
    borderRadius: "10px",
    border: "none",
    background:
      "linear-gradient(135deg, #10b981, #34d399)",
    color: "#ffffff",
    fontSize: "13px",
    fontWeight: "800",
    cursor: "pointer",
    boxShadow:
      "0 7px 18px rgba(79, 70, 229, 0.20)",
  },


  summaryCard: {
    display: "flex",
    justifyContent: "space-between",
    alignItems: "center",
    gap: "20px",
    marginBottom: "20px",
    padding: "24px",
    background: "#ffffff",
    border: "1px solid #e2e8f0",
    borderRadius: "17px",
    boxShadow:
      "0 8px 25px rgba(15, 23, 42, 0.05)",
  },


  card: {
    marginBottom: "20px",
    padding: "24px",
    background: "#ffffff",
    border: "1px solid #e2e8f0",
    borderRadius: "17px",
    boxShadow:
      "0 8px 25px rgba(15, 23, 42, 0.05)",
  },


  sectionLabel: {
    margin: "0 0 5px 0",
    fontSize: "10px",
    fontWeight: "800",
    letterSpacing: "1.2px",
    color: "#94a3b8",
  },


  sectionTitle: {
    margin: 0,
    fontSize: "20px",
    fontWeight: "800",
    color: "#111827",
  },


  sectionDescription: {
    margin: "7px 0 0 0",
    fontSize: "13px",
    color: "#64748b",
  },


  quotaBox: {
    minWidth: "175px",
    padding: "16px 20px",
    borderRadius: "13px",
    background: "#f8fafc",
    border: "1px solid #e2e8f0",
  },


  quotaLabel: {
    display: "block",
    fontSize: "10px",
    fontWeight: "800",
    letterSpacing: "1px",
    color: "#94a3b8",
  },


  quotaNumbers: {
    display: "flex",
    alignItems: "baseline",
    gap: "5px",
    marginTop: "6px",
  },


  quotaUsed: {
    fontSize: "27px",
    fontWeight: "800",
    color: "#111827",
  },


  quotaSlash: {
    fontSize: "18px",
    color: "#94a3b8",
  },


  quotaLimit: {
    fontSize: "16px",
    fontWeight: "700",
    color: "#475569",
  },


  quotaStatus: {
    display: "block",
    marginTop: "4px",
    fontSize: "11px",
    color: "#64748b",
  },


  cardHeader: {
    display: "flex",
    justifyContent: "space-between",
    alignItems: "center",
    gap: "15px",
    marginBottom: "20px",
  },


  memberCountBadge: {
    padding: "8px 12px",
    borderRadius: "999px",
    background: "#eef2ff",
    color: "#4338ca",
    fontSize: "12px",
    fontWeight: "800",
  },


  tableWrapper: {
    overflowX: "auto",
    border:
      "1px solid #e2e8f0",
    borderRadius: "13px",
  },


  table: {
    width: "100%",
    borderCollapse: "collapse",
    minWidth: "850px",
  },


  th: {
    padding: "13px 15px",
    textAlign: "left",
    background: "#f8fafc",
    borderBottom:
      "1px solid #e2e8f0",
    color: "#64748b",
    fontSize: "10px",
    fontWeight: "800",
    letterSpacing: "0.8px",
  },


  tr: {
    borderBottom:
      "1px solid #f1f5f9",
  },


  td: {
    padding: "15px",
    verticalAlign: "middle",
    fontSize: "13px",
    color: "#334155",
  },


  memberCell: {
    display: "flex",
    alignItems: "center",
    gap: "11px",
  },


  avatar: {
    width: "38px",
    height: "38px",
    display: "flex",
    alignItems: "center",
    justifyContent: "center",
    flexShrink: 0,
    borderRadius: "50%",
    background:
      "linear-gradient(135deg, #10b981, #34d399)",
    color: "#ffffff",
    fontSize: "14px",
    fontWeight: "800",
  },


  memberName: {
    display: "block",
    color: "#111827",
    fontSize: "13px",
  },


  memberEmail: {
    display: "block",
    marginTop: "3px",
    color: "#64748b",
    fontSize: "11px",
  },


  ownerBadge: {
    display: "inline-block",
    padding: "6px 10px",
    borderRadius: "999px",
    background: "#fef3c7",
    color: "#92400e",
    fontSize: "10px",
    fontWeight: "800",
  },


  roleSelect: {
    minWidth: "110px",
    padding: "7px 9px",
    border:
      "1px solid #cbd5e1",
    borderRadius: "8px",
    background: "#ffffff",
    color: "#334155",
    fontSize: "12px",
    fontWeight: "700",
    outline: "none",
  },


  statusBadge: {
    display: "inline-flex",
    alignItems: "center",
    gap: "6px",
    padding: "6px 10px",
    borderRadius: "999px",
    background: "#ecfdf5",
    color: "#047857",
    fontSize: "10px",
    fontWeight: "800",
  },


  statusDot: {
    width: "6px",
    height: "6px",
    borderRadius: "50%",
    background: "#10b981",
  },


  dateText: {
    color: "#64748b",
    fontSize: "12px",
  },


  protectedText: {
    color: "#94a3b8",
    fontSize: "11px",
    fontWeight: "700",
  },


  removeButton: {
    padding: "7px 11px",
    border:
      "1px solid #fecaca",
    borderRadius: "8px",
    background: "#fff1f2",
    color: "#dc2626",
    fontSize: "11px",
    fontWeight: "700",
    cursor: "pointer",
  },


  rolesGrid: {
    display: "grid",
    gridTemplateColumns:
      "repeat(auto-fit, minmax(210px, 1fr))",
    gap: "14px",
  },


  roleBox: {
    padding: "17px",
    borderRadius: "13px",
    background: "#f8fafc",
    border:
      "1px solid #e2e8f0",
  },


  roleTitleRow: {
    display: "flex",
    alignItems: "center",
    gap: "8px",
    color: "#111827",
    fontSize: "14px",
  },


  roleIcon: {
    fontSize: "17px",
  },


  roleDescription: {
    margin: "9px 0 0 0",
    fontSize: "12px",
    lineHeight: "1.55",
    color: "#64748b",
  },


  emptyState: {
    padding: "55px 20px",
    textAlign: "center",
  },


  emptyIcon: {
    fontSize: "38px",
    marginBottom: "10px",
  },


  emptyTitle: {
    margin: 0,
    fontSize: "18px",
    color: "#111827",
  },


  emptyText: {
    margin: "7px 0 18px 0",
    color: "#64748b",
    fontSize: "13px",
  },


  successAlert: {
    display: "flex",
    alignItems: "center",
    gap: "9px",
    marginBottom: "18px",
    padding: "12px 15px",
    borderRadius: "10px",
    background: "#ecfdf5",
    border:
      "1px solid #a7f3d0",
    color: "#047857",
    fontSize: "13px",
    fontWeight: "600",
  },


  errorAlert: {
    display: "flex",
    alignItems: "center",
    gap: "9px",
    marginBottom: "18px",
    padding: "12px 15px",
    borderRadius: "10px",
    background: "#fff1f2",
    border:
      "1px solid #fecaca",
    color: "#b91c1c",
    fontSize: "13px",
    fontWeight: "600",
  },


  alertIcon: {
    width: "22px",
    height: "22px",
    display: "flex",
    alignItems: "center",
    justifyContent: "center",
    borderRadius: "50%",
    background: "#10b981",
    color: "#ffffff",
    fontSize: "12px",
    fontWeight: "800",
  },


  errorAlertIcon: {
    width: "22px",
    height: "22px",
    display: "flex",
    alignItems: "center",
    justifyContent: "center",
    borderRadius: "50%",
    background: "#dc2626",
    color: "#ffffff",
    fontSize: "12px",
    fontWeight: "800",
  },


  modalOverlay: {
    position: "fixed",
    inset: 0,
    zIndex: 1000,
    display: "flex",
    alignItems: "center",
    justifyContent: "center",
    padding: "20px",
    background:
      "rgba(15, 23, 42, 0.55)",
    backdropFilter: "blur(4px)",
  },


  modal: {
    width: "100%",
    maxWidth: "470px",
    padding: "25px",
    boxSizing: "border-box",
    borderRadius: "17px",
    background: "#ffffff",
    boxShadow:
      "0 25px 60px rgba(15, 23, 42, 0.25)",
  },


  modalHeader: {
    display: "flex",
    justifyContent: "space-between",
    alignItems: "flex-start",
    gap: "15px",
  },


  modalTitle: {
    margin: 0,
    fontSize: "21px",
    fontWeight: "800",
    color: "#111827",
  },


  modalDescription: {
    margin: "10px 0 20px 0",
    fontSize: "13px",
    lineHeight: "1.5",
    color: "#64748b",
  },


  closeButton: {
    width: "32px",
    height: "32px",
    border: "none",
    borderRadius: "8px",
    background: "#f1f5f9",
    color: "#475569",
    fontSize: "22px",
    lineHeight: "1",
    cursor: "pointer",
  },


  formLabel: {
    display: "block",
    marginBottom: "7px",
    fontSize: "11px",
    fontWeight: "800",
    color: "#475569",
    textTransform: "uppercase",
    letterSpacing: "0.5px",
  },


  input: {
    width: "100%",
    boxSizing: "border-box",
    marginBottom: "17px",
    padding: "11px 12px",
    border:
      "1px solid #cbd5e1",
    borderRadius: "9px",
    background: "#ffffff",
    color: "#1e293b",
    fontSize: "13px",
    outline: "none",
  },


  inviteInfo: {
    display: "flex",
    alignItems: "flex-start",
    gap: "8px",
    marginBottom: "20px",
    padding: "11px",
    borderRadius: "9px",
    background: "#eff6ff",
    border:
      "1px solid #bfdbfe",
    color: "#1d4ed8",
    fontSize: "11px",
    lineHeight: "1.5",
  },


  inviteInfoIcon: {
    fontWeight: "800",
  },


  modalActions: {
    display: "flex",
    justifyContent: "flex-end",
    gap: "10px",
  },


  cancelButton: {
    padding: "10px 15px",
    border:
      "1px solid #cbd5e1",
    borderRadius: "9px",
    background: "#ffffff",
    color: "#475569",
    fontSize: "12px",
    fontWeight: "700",
    cursor: "pointer",
  },


  inviteSubmitButton: {
    padding: "10px 17px",
    border: "none",
    borderRadius: "9px",
    background:
      "linear-gradient(135deg, #10b981, #34d399)",
    color: "#ffffff",
    fontSize: "12px",
    fontWeight: "800",
    cursor: "pointer",
  },


  loading: {
    minHeight: "500px",
    display: "flex",
    flexDirection: "column",
    alignItems: "center",
    justifyContent: "center",
    color: "#64748b",
  },


  loadingTitle: {
    margin: "10px 0 5px 0",
    color: "#111827",
    fontSize: "19px",
  },


  loadingText: {
    margin: 0,
    fontSize: "13px",
  },


  spinner: {
    width: "36px",
    height: "36px",
    border:
      "4px solid #e2e8f0",
    borderTop:
      "4px solid #10b981",
    borderRadius: "50%",
    animation:
      "spin 1s linear infinite",
  },

};


export default TeamMembers;