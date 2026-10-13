import { useEffect, useState } from "react";
import api from "../services/api";


/* =========================================================
   USAGE PAGE
   ========================================================= */

function Usage() {
  const [usage, setUsage] = useState(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");

  /* ---------------------------------------------------------
     GET ORGANIZATION ID
     --------------------------------------------------------- */

  const getOrganizationId = () => {
    try {
      const user = JSON.parse(
        localStorage.getItem("user") || "{}"
      );

      return (
        user.organization ||
        localStorage.getItem("organization_id") ||
        ""
      );
    } catch {
      return localStorage.getItem("organization_id") || "";
    }
  };


  /* ---------------------------------------------------------
     FETCH USAGE
     --------------------------------------------------------- */

  const fetchUsage = async () => {
    try {
      setLoading(true);
      setError("");

      const organizationId = getOrganizationId();

      if (!organizationId) {
        throw new Error(
          "Organization information is not available."
        );
      }

      const response = await api.get(
        `/organizations/${organizationId}/usage`
      );

      setUsage(response.data);

    } catch (err) {
      console.error(
        "[USAGE FETCH ERROR]",
        err
      );

      const message =
        err.response?.data?.detail ||
        err.message ||
        "Failed to load organization usage.";

      setError(message);

    } finally {
      setLoading(false);
    }
  };


  /* ---------------------------------------------------------
     INITIAL LOAD
     --------------------------------------------------------- */

  useEffect(() => {
    fetchUsage();
  }, []);


  /* ---------------------------------------------------------
     LOADING STATE
     --------------------------------------------------------- */

  if (loading) {
    return (
      <div style={styles.page}>
        <div style={styles.loadingCard}>
          <div style={styles.spinner}></div>

          <p style={styles.loadingText}>
            Loading SaaS usage...
          </p>
        </div>
      </div>
    );
  }


  /* ---------------------------------------------------------
     ERROR STATE
     --------------------------------------------------------- */

  if (error) {
    return (
      <div style={styles.page}>
        <div style={styles.errorCard}>

          <div style={styles.errorIcon}>
            !
          </div>

          <h2 style={styles.errorTitle}>
            Unable to Load Usage
          </h2>

          <p style={styles.errorText}>
            {error}
          </p>

          <button
            onClick={fetchUsage}
            style={styles.retryButton}
          >
            Retry
          </button>

        </div>
      </div>
    );
  }


  /* ---------------------------------------------------------
     EXTRACT DATA
     --------------------------------------------------------- */

  const usageData = usage?.usage || {};

  const plan =
    usageData.plan || "free";

  const organizationStatus =
    usageData.organization_status || "unknown";

  const quotas =
    usageData.quotas || {};


  /* ---------------------------------------------------------
     QUOTA CARD
     --------------------------------------------------------- */

  const quotaCards = [
    {
      key: "aws_accounts",
      title: "AWS Accounts",
      icon: "AWS",
      suffix: "",
    },
    {
      key: "team_members",
      title: "Team Members",
      icon: "TEAM",
      suffix: "",
    },
    {
      key: "scans",
      title: "Scans This Month",
      icon: "SCAN",
      suffix: "",
    },
    {
      key: "reports",
      title: "Reports This Month",
      icon: "REPORT",
      suffix: "",
    },
    {
      key: "storage_mb",
      title: "Storage",
      icon: "DATA",
      suffix: " MB",
    },
  ];


  /* ---------------------------------------------------------
     RENDER
     --------------------------------------------------------- */

  return (
    <div style={styles.page}>

      {/* =====================================================
          HEADER
      ====================================================== */}

      <div style={styles.header}>

        <div>
          <p style={styles.eyebrow}>
            SAAS MANAGEMENT
          </p>

          <h1 style={styles.title}>
            Usage & Quota
          </h1>

          <p style={styles.subtitle}>
            Monitor your organization's resource
            consumption and subscription limits.
          </p>
        </div>


        <div style={styles.headerActions}>

          <div style={styles.planBadge}>
            <span style={styles.planDot}></span>

            {String(plan).toUpperCase()} PLAN
          </div>

          <div style={styles.statusBadge}>
            {organizationStatus}
          </div>

        </div>

      </div>


      {/* =====================================================
          OVERVIEW
      ====================================================== */}

      <div style={styles.overviewCard}>

        <div>
          <p style={styles.overviewLabel}>
            CURRENT PLAN
          </p>

          <h2 style={styles.planName}>
            {String(plan).charAt(0).toUpperCase() +
              String(plan).slice(1)}
          </h2>

          <p style={styles.planDescription}>
            Your organization's current SaaS
            resource allocation.
          </p>
        </div>


        <div style={styles.overviewRight}>

          <div style={styles.statusCircle}>
            ✓
          </div>

          <div>
            <p style={styles.activeTitle}>
              Organization Active
            </p>

            <p style={styles.activeText}>
              Services are available
            </p>
          </div>

        </div>

      </div>


      {/* =====================================================
          RESOURCE USAGE
      ====================================================== */}

      <div style={styles.sectionHeader}>

        <div>
          <h2 style={styles.sectionTitle}>
            Resource Usage
          </h2>

          <p style={styles.sectionSubtitle}>
            Current usage against your subscription quotas.
          </p>
        </div>


        <button
          onClick={fetchUsage}
          style={styles.refreshButton}
        >
          ↻ Refresh
        </button>

      </div>


      <div style={styles.grid}>

        {quotaCards.map((card) => {

          const data =
            quotas[card.key] || {};

          const used =
            Number(data.used || 0);

          const limit =
            Number(data.limit || 0);

          const percentage =
            Number(data.percentage_used || 0);

          const remaining =
            data.remaining;

          const unlimited =
            Boolean(data.unlimited);

          return (
            <div
              key={card.key}
              style={styles.quotaCard}
            >

              {/* CARD HEADER */}

              <div style={styles.cardHeader}>

                <div style={styles.iconBox}>
                  {card.icon}
                </div>

                <div style={styles.cardTitleArea}>

                  <h3 style={styles.cardTitle}>
                    {card.title}
                  </h3>

                  <p style={styles.cardUsage}>
                    {used}
                    {card.suffix} used
                  </p>

                </div>

              </div>


              {/* NUMBERS */}

              <div style={styles.numberRow}>

                <span style={styles.usedNumber}>
                  {used}
                  {card.suffix}
                </span>

                <span style={styles.limitNumber}>
                  {unlimited
                    ? "Unlimited"
                    : `/ ${limit}${card.suffix}`}
                </span>

              </div>


              {/* PROGRESS BAR */}

              <div style={styles.progressBackground}>

                <div
                  style={{
                    ...styles.progressBar,
                    width: unlimited
                      ? "8%"
                      : `${Math.min(
                          Math.max(percentage, 0),
                          100
                        )}%`,
                  }}
                ></div>

              </div>


              {/* FOOTER */}

              <div style={styles.cardFooter}>

                <span>
                  {unlimited
                    ? "Unlimited"
                    : `${remaining}${card.suffix} remaining`}
                </span>

                <span>
                  {unlimited
                    ? "∞"
                    : `${percentage}%`}
                </span>

              </div>

            </div>
          );
        })}

      </div>


      {/* =====================================================
          SaaS INFORMATION
      ====================================================== */}

      <div style={styles.infoCard}>

        <div style={styles.infoIcon}>
          ⓘ
        </div>

        <div>

          <h3 style={styles.infoTitle}>
            About Usage Limits
          </h3>

          <p style={styles.infoText}>
            Usage limits are applied at the organization
            level. Scans and reports are tracked monthly,
            while AWS accounts, team members, and storage
            are tracked against your subscription allocation.
          </p>

        </div>

      </div>

    </div>
  );
}


/* =========================================================
   STYLES
   ========================================================= */

const styles = {

  page: {
    minHeight: "100%",
    padding: "32px",
    background:
      "linear-gradient(135deg, #f8fafc 0%, #eef2ff 100%)",
    boxSizing: "border-box",
  },

  header: {
    display: "flex",
    justifyContent: "space-between",
    alignItems: "flex-start",
    gap: "24px",
    marginBottom: "28px",
  },

  eyebrow: {
    margin: "0 0 8px 0",
    fontSize: "12px",
    fontWeight: "700",
    letterSpacing: "1.5px",
    color: "#34d399",
  },

  title: {
    margin: 0,
    fontSize: "32px",
    fontWeight: "800",
    color: "#111827",
  },

  subtitle: {
    margin: "8px 0 0 0",
    fontSize: "15px",
    color: "#64748b",
  },

  headerActions: {
    display: "flex",
    alignItems: "center",
    gap: "10px",
    flexWrap: "wrap",
  },

  planBadge: {
    display: "flex",
    alignItems: "center",
    gap: "8px",
    padding: "10px 14px",
    borderRadius: "999px",
    background: "#eef2ff",
    color: "#4338ca",
    fontSize: "12px",
    fontWeight: "800",
  },

  planDot: {
    width: "8px",
    height: "8px",
    borderRadius: "50%",
    background: "#10b981",
  },

  statusBadge: {
    padding: "10px 14px",
    borderRadius: "999px",
    background: "#ecfdf5",
    color: "#047857",
    fontSize: "12px",
    fontWeight: "700",
    textTransform: "capitalize",
  },

  overviewCard: {
    display: "flex",
    justifyContent: "space-between",
    alignItems: "center",
    gap: "24px",
    padding: "26px",
    marginBottom: "32px",
    background: "#ffffff",
    border: "1px solid #e2e8f0",
    borderRadius: "18px",
    boxShadow:
      "0 10px 30px rgba(15, 23, 42, 0.06)",
  },

  overviewLabel: {
    margin: "0 0 5px 0",
    fontSize: "11px",
    fontWeight: "800",
    letterSpacing: "1px",
    color: "#94a3b8",
  },

  planName: {
    margin: 0,
    fontSize: "25px",
    fontWeight: "800",
    color: "#111827",
    textTransform: "capitalize",
  },

  planDescription: {
    margin: "6px 0 0 0",
    color: "#64748b",
    fontSize: "14px",
  },

  overviewRight: {
    display: "flex",
    alignItems: "center",
    gap: "12px",
  },

  statusCircle: {
    width: "42px",
    height: "42px",
    display: "flex",
    alignItems: "center",
    justifyContent: "center",
    borderRadius: "50%",
    background: "#dcfce7",
    color: "#15803d",
    fontSize: "20px",
    fontWeight: "800",
  },

  activeTitle: {
    margin: 0,
    fontSize: "14px",
    fontWeight: "700",
    color: "#166534",
  },

  activeText: {
    margin: "3px 0 0 0",
    fontSize: "12px",
    color: "#64748b",
  },

  sectionHeader: {
    display: "flex",
    justifyContent: "space-between",
    alignItems: "center",
    marginBottom: "16px",
  },

  sectionTitle: {
    margin: 0,
    fontSize: "21px",
    fontWeight: "800",
    color: "#111827",
  },

  sectionSubtitle: {
    margin: "5px 0 0 0",
    fontSize: "13px",
    color: "#64748b",
  },

  refreshButton: {
    border: "1px solid #cbd5e1",
    background: "#ffffff",
    color: "#334155",
    borderRadius: "10px",
    padding: "9px 14px",
    cursor: "pointer",
    fontSize: "13px",
    fontWeight: "700",
  },

  grid: {
    display: "grid",
    gridTemplateColumns:
      "repeat(auto-fit, minmax(240px, 1fr))",
    gap: "18px",
  },

  quotaCard: {
    background: "#ffffff",
    border: "1px solid #e2e8f0",
    borderRadius: "16px",
    padding: "20px",
    boxShadow:
      "0 8px 25px rgba(15, 23, 42, 0.05)",
  },

  cardHeader: {
    display: "flex",
    alignItems: "center",
    gap: "12px",
  },

  iconBox: {
    width: "42px",
    height: "42px",
    display: "flex",
    alignItems: "center",
    justifyContent: "center",
    borderRadius: "12px",
    background: "#f1f5f9",
    fontSize: "19px",
  },

  cardTitleArea: {
    minWidth: 0,
  },

  cardTitle: {
    margin: 0,
    fontSize: "14px",
    fontWeight: "750",
    color: "#1e293b",
  },

  cardUsage: {
    margin: "4px 0 0 0",
    fontSize: "12px",
    color: "#64748b",
  },

  numberRow: {
    display: "flex",
    alignItems: "baseline",
    gap: "5px",
    marginTop: "22px",
  },

  usedNumber: {
    fontSize: "27px",
    fontWeight: "800",
    color: "#111827",
  },

  limitNumber: {
    fontSize: "13px",
    color: "#94a3b8",
    fontWeight: "600",
  },

  progressBackground: {
    height: "8px",
    marginTop: "14px",
    overflow: "hidden",
    borderRadius: "999px",
    background: "#e2e8f0",
  },

  progressBar: {
    height: "100%",
    borderRadius: "999px",
    background:
      "linear-gradient(90deg, #10b981, #34d399)",
    transition: "width 0.4s ease",
  },

  cardFooter: {
    display: "flex",
    justifyContent: "space-between",
    gap: "10px",
    marginTop: "11px",
    fontSize: "11px",
    color: "#64748b",
  },

  infoCard: {
    display: "flex",
    gap: "14px",
    marginTop: "24px",
    padding: "20px",
    background: "#ffffff",
    border: "1px solid #dbeafe",
    borderRadius: "15px",
  },

  infoIcon: {
    fontSize: "22px",
    color: "#34d399",
  },

  infoTitle: {
    margin: "0 0 5px 0",
    fontSize: "14px",
    fontWeight: "800",
    color: "#1e3a8a",
  },

  infoText: {
    margin: 0,
    fontSize: "13px",
    lineHeight: "1.6",
    color: "#64748b",
  },

  loadingCard: {
    minHeight: "400px",
    display: "flex",
    flexDirection: "column",
    alignItems: "center",
    justifyContent: "center",
  },

  spinner: {
    width: "36px",
    height: "36px",
    border: "4px solid #e2e8f0",
    borderTop: "4px solid #10b981",
    borderRadius: "50%",
    animation: "spin 1s linear infinite",
  },

  loadingText: {
    marginTop: "15px",
    color: "#64748b",
    fontSize: "14px",
  },

  errorCard: {
    maxWidth: "500px",
    margin: "80px auto",
    padding: "35px",
    textAlign: "center",
    background: "#ffffff",
    border: "1px solid #fecaca",
    borderRadius: "18px",
    boxShadow:
      "0 10px 30px rgba(15, 23, 42, 0.06)",
  },

  errorIcon: {
    width: "45px",
    height: "45px",
    display: "flex",
    alignItems: "center",
    justifyContent: "center",
    margin: "0 auto 15px auto",
    borderRadius: "50%",
    background: "#fee2e2",
    color: "#dc2626",
    fontSize: "22px",
    fontWeight: "800",
  },

  errorTitle: {
    margin: 0,
    fontSize: "20px",
    color: "#991b1b",
  },

  errorText: {
    margin: "10px 0 20px 0",
    fontSize: "14px",
    color: "#64748b",
  },

  retryButton: {
    border: "none",
    background: "#10b981",
    color: "#ffffff",
    borderRadius: "10px",
    padding: "10px 20px",
    cursor: "pointer",
    fontWeight: "700",
  },

};


export default Usage;