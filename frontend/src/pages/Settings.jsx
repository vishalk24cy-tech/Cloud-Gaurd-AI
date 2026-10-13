import { useEffect, useState } from "react";
import { FileText, HardDrive, RefreshCw, Search, Users } from "lucide-react";
import api from "../services/api";
import RemediationGovernanceSettings from "../components/RemediationGovernanceSettings";
import "./Settings.css";

function Settings() {
  const [organization, setOrganization] = useState(null);
  const [subscription, setSubscription] = useState(null);
  const [trial, setTrial] = useState(null);
  const [usageData, setUsageData] = useState(null);

  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");

  const [checkoutLoading, setCheckoutLoading] = useState(false);
  const [checkoutError, setCheckoutError] = useState("");
  const [checkoutSuccess, setCheckoutSuccess] = useState("");
  const [refreshKey, setRefreshKey] = useState(0);

  // ============================================================
  // GET ORGANIZATION ID
  // ============================================================

  const getOrganizationId = () => {
    try {
      const user = JSON.parse(
        localStorage.getItem("user") || "{}"
      );

      return (
        user.organization ||
        user.organization_id ||
        null
      );
    } catch (error) {
      console.error(
        "Unable to read logged-in user:",
        error
      );

      return null;
    }
  };

  // ============================================================
  // LOAD SETTINGS DATA
  // ============================================================

  const loadSettings = async () => {
    try {
      setLoading(true);
      setError("");
      setCheckoutError("");
      setCheckoutSuccess("");
      setRefreshKey((prev) => prev + 1);

      const organizationId = getOrganizationId();

      if (!organizationId) {
        throw new Error("Organization ID not found.");
      }

      // --------------------------------------------------------
      // Organization
      // --------------------------------------------------------

      const organizationResponse = await api.get(
        `/organizations/${organizationId}`
      );

      setOrganization(
        organizationResponse.data
      );

      // --------------------------------------------------------
      // Subscription
      // --------------------------------------------------------

      try {
        const subscriptionResponse =
          await api.get(
            `/organizations/${organizationId}/subscription`
          );

        setSubscription(
          subscriptionResponse.data
        );
      } catch (subscriptionError) {
        console.error(
          "Subscription loading error:",
          subscriptionError
        );

        setSubscription(null);
      }

      // --------------------------------------------------------
      // Trial
      // --------------------------------------------------------

      try {
        const trialResponse =
          await api.get(
            `/organizations/${organizationId}/trial`
          );

        setTrial(
          trialResponse.data
        );
      } catch (trialError) {
        console.error(
          "Trial loading error:",
          trialError
        );

        setTrial(null);
      }

      // --------------------------------------------------------
      // Usage
      // --------------------------------------------------------

      try {
        const usageResponse =
          await api.get(
            `/organizations/${organizationId}/usage`
          );

        setUsageData(
          usageResponse.data?.usage ||
          usageResponse.data ||
          null
        );
      } catch (usageError) {
        console.error(
          "Usage loading error:",
          usageError
        );

        setUsageData(null);
      }
    } catch (loadError) {
      console.error(
        "Settings loading error:",
        loadError
      );

      setError(
        loadError.response?.data?.detail ||
        loadError.message ||
        "Unable to load organization settings."
      );
    } finally {
      setLoading(false);
    }
  };

  // ============================================================
  // INITIAL LOAD
  // ============================================================

  useEffect(() => {
    loadSettings();
  }, []);

  // ============================================================
  // RAZORPAY CHECKOUT
  // ============================================================

  const handleUpgrade = async () => {
    try {
      setCheckoutLoading(true);
      setCheckoutError("");
      setCheckoutSuccess("");

      const user = JSON.parse(
        localStorage.getItem("user") || "{}"
      );

      const organizationId =
        user.organization ||
        user.organization_id;

      if (!organizationId) {
        throw new Error(
          "Organization ID not found."
        );
      }

      // --------------------------------------------------------
      // CREATE RAZORPAY ORDER
      // --------------------------------------------------------

      const response = await api.post(
        `/subscriptions/${organizationId}/checkout`,
        {
          plan: "pro",
          billing_cycle: "monthly",
        }
      );

      const checkout =
        response.data?.checkout;

      if (!checkout?.order_id) {
        throw new Error(
          "Razorpay order was not created."
        );
      }

      // --------------------------------------------------------
      // LOAD RAZORPAY CHECKOUT SCRIPT
      // --------------------------------------------------------

      if (!window.Razorpay) {
        await new Promise(
          (resolve, reject) => {
            const script =
              document.createElement(
                "script"
              );

            script.src =
              "https://checkout.razorpay.com/v1/checkout.js";

            script.onload = resolve;

            script.onerror = () =>
              reject(
                new Error(
                  "Unable to load Razorpay Checkout."
                )
              );

            document.body.appendChild(
              script
            );
          }
        );
      }

      // --------------------------------------------------------
      // RAZORPAY OPTIONS
      // --------------------------------------------------------

      const options = {
        key: checkout.razorpay_key_id,

        amount: checkout.amount,

        currency: checkout.currency,

        name: "CloudGuardAI",

        description:
          "CloudGuardAI Pro Monthly Subscription",

        order_id: checkout.order_id,

        // ------------------------------------------------------
        // CUSTOMER PREFILL
        // ------------------------------------------------------

        prefill: {
          email: user.email || "",
          name: user.name || "",
        },

        // ------------------------------------------------------
        // CHECKOUT THEME
        // ------------------------------------------------------

        theme: {
          color: "#10b981",
        },

        // ------------------------------------------------------
        // PAYMENT SUCCESS
        // ------------------------------------------------------

        handler: async function (
          paymentResponse
        ) {
          try {
            setCheckoutLoading(true);
            setCheckoutError("");
            setCheckoutSuccess("");

            const verificationResponse =
              await api.post(
                `/subscriptions/${organizationId}/verify-payment`,
                {
                  razorpay_order_id:
                    paymentResponse.razorpay_order_id,

                  razorpay_payment_id:
                    paymentResponse.razorpay_payment_id,

                  razorpay_signature:
                    paymentResponse.razorpay_signature,
                }
              );

            if (
              verificationResponse.data
                ?.verified === true
            ) {
              setCheckoutSuccess(
                "Payment verified successfully. Your Pro plan is now active."
              );

              await loadSettings();
            } else {
              throw new Error(
                "Payment verification failed."
              );
            }
          } catch (verificationError) {
            console.error(
              "Payment verification error:",
              verificationError
            );

            setCheckoutError(
              verificationError.response
                ?.data?.detail ||
              verificationError.message ||
              "Payment verification failed."
            );
          } finally {
            setCheckoutLoading(false);
          }
        },

        // ------------------------------------------------------
        // MODAL DISMISSED
        // ------------------------------------------------------

        modal: {
          ondismiss: function () {
            setCheckoutLoading(false);
          },
        },
      };

      // --------------------------------------------------------
      // CREATE RAZORPAY INSTANCE
      // --------------------------------------------------------

      const razorpay =
        new window.Razorpay(
          options
        );

      // --------------------------------------------------------
      // PAYMENT FAILED
      // --------------------------------------------------------

      razorpay.on(
        "payment.failed",
        function (response) {
          console.error(
            "Razorpay payment failed:",
            response.error
          );

          setCheckoutError(
            response.error
              ?.description ||
            "Payment failed."
          );

          setCheckoutLoading(false);
        }
      );

      // --------------------------------------------------------
      // OPEN CHECKOUT
      // --------------------------------------------------------

      razorpay.open();
    } catch (checkoutException) {
      console.error(
        "Checkout error:",
        checkoutException
      );

      setCheckoutError(
        checkoutException.response
          ?.data?.detail ||
        checkoutException.message ||
        "Unable to start checkout."
      );

      setCheckoutLoading(false);
    }
  };

  // ============================================================
  // DERIVED DATA
  // ============================================================

  const usage =
    usageData || {};

  const quotas =
    usage.quotas || {};

  const plan = String(
    usage.plan ||
    subscription?.plan_name ||
    subscription?.plan?.name ||
    organization?.plan ||
    "free"
  ).toLowerCase();

  const organizationStatus =
    usage.organization_status ||
    subscription?.organization_status ||
    organization?.status ||
    "active";

  const subscriptionStatus =
    subscription?.status ||
    "active";

  const billingProvider =
    subscription?.billing_provider ||
    subscription?.provider ||
    "Not connected";

  const billingCycle =
    subscription?.billing_cycle ||
    "monthly";

  const trialDays =
    trial?.days_remaining ??
    trial?.remaining_days ??
    null;

  const isPro =
    plan === "pro";

  const isBusiness =
    plan === "business";

  const currentPeriodStart =
    subscription?.current_period_start;

  const currentPeriodEnd =
    subscription?.current_period_end;

  const cancelAtPeriodEnd =
    subscription?.cancel_at_period_end === true;

  // ============================================================
  // HELPERS
  // ============================================================

  const formatDate = (value) => {
    if (!value) {
      return "Not available";
    }

    const date = new Date(value);

    if (Number.isNaN(date.getTime())) {
      return "Not available";
    }

    return date.toLocaleDateString(
      undefined,
      {
        day: "2-digit",
        month: "short",
        year: "numeric",
      }
    );
  };

  const formatPlanName = (value) => {
    if (!value) {
      return "Free";
    }

    return (
      String(value)
        .charAt(0)
        .toUpperCase() +
      String(value).slice(1)
    );
  };

  const getPlanPrice = () => {
    if (plan === "pro") {
      return "₹29";
    }

    if (plan === "business") {
      return "₹99";
    }

    return "₹0";
  };

  // ============================================================
  // LOADING SCREEN
  // ============================================================

  if (loading) {
    return (
      <div style={styles.loading}>
        <div style={styles.spinner}></div>

        <strong>
          Loading Organization Settings...
        </strong>

        <p>
          Please wait while CloudGuardAI
          loads your SaaS configuration.
        </p>
      </div>
    );
  }

  // ============================================================
  // ERROR SCREEN
  // ============================================================

  if (error) {
    return (
      <div style={styles.errorCard}>
        <div style={styles.errorIcon}>
          !
        </div>

        <h2>
          Unable to Load Settings
        </h2>

        <p>
          {error}
        </p>

        <button
          type="button"
          onClick={loadSettings}
          style={styles.retryButton}
        >
          Retry
        </button>
      </div>
    );
  }

  // ============================================================
  // RENDER
  // ============================================================

  return (
    <div className="settings-phase5" style={styles.page}>

      {/* =====================================================
          PAGE HEADER
          ====================================================== */}

      <div style={styles.header}>

        <div>
          <p style={styles.eyebrow}>
            SAAS MANAGEMENT
          </p>

          <h1 style={styles.title}>
            Organization Settings
          </h1>

          <p style={styles.subtitle}>
            Manage your CloudGuardAI organization,
            subscription and SaaS resources.
          </p>
        </div>

        <button
          type="button"
          onClick={loadSettings}
          style={styles.refreshButton}
        >
          <RefreshCw size={14} /> Refresh
        </button>

      </div>

      {/* =====================================================
          ORGANIZATION
          ====================================================== */}

      <section style={styles.card}>

        <div style={styles.cardHeader}>

          <div>
            <p style={styles.sectionLabel}>
              ORGANIZATION
            </p>

            <h2 style={styles.sectionTitle}>
              Organization Information
            </h2>
          </div>

          <span style={styles.activeBadge}>
            ● {organizationStatus}
          </span>

        </div>

        <div style={styles.infoGrid}>

          <div style={styles.infoItem}>
            <span style={styles.infoLabel}>
              Organization Name
            </span>

            <strong style={styles.infoValue}>
              {organization?.name ||
                "CloudGuardAI Organization"}
            </strong>
          </div>

          <div style={styles.infoItem}>
            <span style={styles.infoLabel}>
              Organization ID
            </span>

            <strong style={styles.infoValueSmall}>
              {usage?.organization_id ||
                organization?._id ||
                organization?.id ||
                "Not available"}
            </strong>
          </div>

          <div style={styles.infoItem}>
            <span style={styles.infoLabel}>
              Status
            </span>

            <strong style={styles.successText}>
              Active
            </strong>
          </div>

          <div style={styles.infoItem}>
            <span style={styles.infoLabel}>
              Platform
            </span>

            <strong style={styles.infoValue}>
              CloudGuardAI
            </strong>
          </div>

        </div>

      </section>

      {/* =====================================================
          SUBSCRIPTION
          ====================================================== */}

      <section style={styles.card}>

        <div style={styles.cardHeader}>

          <div>
            <p style={styles.sectionLabel}>
              SUBSCRIPTION
            </p>

            <h2 style={styles.sectionTitle}>
              Plan & Billing
            </h2>
          </div>

          <div
            style={{
              ...styles.planBadge,
              ...(isPro
                ? styles.proBadge
                : {}),
            }}
          >
            {String(plan).toUpperCase()}
          </div>

        </div>

        {/* ===================================================
            CURRENT PLAN SUMMARY
            =================================================== */}

        <div style={styles.billingHero}>

          <div style={styles.billingHeroLeft}>

            <div style={styles.planIcon}>
              {isBusiness
                ? "◆"
                : isPro
                ? "★"
                : "○"}
            </div>

            <div>

              <span style={styles.infoLabel}>
                CURRENT PLAN
              </span>

              <div style={styles.currentPlanRow}>

                <h3 style={styles.currentPlanName}>
                  {formatPlanName(plan)}
                </h3>

                {isPro && (
                  <span style={styles.activePlanBadge}>
                    ACTIVE
                  </span>
                )}

              </div>

              <p style={styles.planText}>
                {isBusiness
                  ? "Business SaaS plan with advanced organization capabilities."
                  : isPro
                  ? "Pro plan with enhanced CloudGuardAI security capabilities."
                  : "Free plan with basic CloudGuardAI capabilities."}
              </p>

            </div>

          </div>

          <div style={styles.priceBox}>

            <span style={styles.price}>
              {getPlanPrice()}
            </span>

            {plan !== "free" && (
              <span style={styles.pricePeriod}>
                / month
              </span>
            )}

          </div>

        </div>

        {/* ===================================================
            BILLING DETAILS
            =================================================== */}

        <div style={styles.subscriptionGrid}>

          <div style={styles.planBox}>

            <span style={styles.infoLabel}>
              SUBSCRIPTION STATUS
            </span>

            <h3
              style={{
                ...styles.subscriptionStatus,
                color:
                  subscriptionStatus ===
                  "active"
                    ? "#15803d"
                    : "#b45309",
              }}
            >
              {String(
                subscriptionStatus
              )}
            </h3>

            <p style={styles.planText}>
              Current subscription lifecycle status.
            </p>

          </div>

          <div style={styles.planBox}>

            <span style={styles.infoLabel}>
              BILLING PROVIDER
            </span>

            <h3 style={styles.billingText}>
              {billingProvider}
            </h3>

            <p style={styles.planText}>
              Payment provider connected to this
              organization.
            </p>

          </div>

          <div style={styles.planBox}>

            <span style={styles.infoLabel}>
              BILLING CYCLE
            </span>

            <h3 style={styles.billingText}>
              {formatPlanName(
                billingCycle
              )}
            </h3>

            <p style={styles.planText}>
              Current billing frequency.
            </p>

          </div>

        </div>

        {/* ===================================================
            PERIOD INFORMATION
            =================================================== */}

        {(currentPeriodStart ||
          currentPeriodEnd) && (
          <div style={styles.periodBox}>

            <div>
              <span style={styles.infoLabel}>
                CURRENT PERIOD
              </span>

              <strong style={styles.periodValue}>
                {formatDate(
                  currentPeriodStart
                )}
                {" → "}
                {formatDate(
                  currentPeriodEnd
                )}
              </strong>
            </div>

            {cancelAtPeriodEnd && (
              <span style={styles.cancelBadge}>
                Cancellation scheduled
              </span>
            )}

          </div>
        )}

        {/* ===================================================
            BILLING ACTION
            =================================================== */}

        <div style={styles.billingActions}>

          {!isPro && !isBusiness ? (
            <button
              type="button"
              onClick={handleUpgrade}
              disabled={checkoutLoading}
              style={{
                ...styles.upgradeButton,
                opacity:
                  checkoutLoading
                    ? 0.7
                    : 1,
                cursor:
                  checkoutLoading
                    ? "not-allowed"
                    : "pointer",
              }}
            >
              {checkoutLoading
                ? "Processing..."
                : "Upgrade to Pro — ₹29/month"}
            </button>
          ) : (
            <div style={styles.currentPlanMessage}>
              <span style={styles.currentPlanCheck}>
                ✓
              </span>

              <div>
                <strong>
                  {isBusiness
                    ? "Business plan is active"
                    : "Pro plan is active"}
                </strong>

                <p>
                  Your organization is currently
                  subscribed to the{" "}
                  {formatPlanName(plan)} plan.
                </p>
              </div>
            </div>
          )}

          <p style={styles.billingNote}>
            Razorpay Test Mode • No real money
            will be charged.
          </p>

          {checkoutSuccess && (
            <div style={styles.checkoutSuccess}>
              ✓ {checkoutSuccess}
            </div>
          )}

          {checkoutError && (
            <div style={styles.checkoutError}>
              {checkoutError}
            </div>
          )}

        </div>

      </section>

      {/* =====================================================
          TRIAL
          ====================================================== */}

      <section style={styles.card}>

        <div style={styles.cardHeader}>

          <div>
            <p style={styles.sectionLabel}>
              FREE TRIAL
            </p>

            <h2 style={styles.sectionTitle}>
              Trial Status
            </h2>
          </div>

        </div>

        <div style={styles.trialBox}>

          <div>
            <span style={styles.infoLabel}>
              TRIAL STATUS
            </span>

            <h3
              style={{
                ...styles.trialTitle,
                color: trial?.trial_active
                  ? "#15803d"
                  : "#64748b",
              }}
            >
              {trial?.subscription_active
                ? "Not Active"
                : trial?.trial_active
                ? "Active"
                : trial?.trial_expired
                ? "Expired"
                : "Not Active"}
            </h3>
          </div>

          <div>
            <span style={styles.infoLabel}>
              REMAINING
            </span>

            <h3 style={styles.trialDays}>
              {trialDays !== null
                ? `${trialDays} days`
                : "0 days"}
            </h3>
          </div>

          <div>
            <span style={styles.infoLabel}>
              TRIAL END
            </span>

            <h3 style={styles.trialEnd}>
              {trial?.trial_ends_at
                ? formatDate(
                    trial.trial_ends_at
                  )
                : "Not available"}
            </h3>
          </div>

        </div>

      </section>

      {/* =====================================================
          USAGE SUMMARY
          ====================================================== */}

      <section style={styles.card}>

        <div style={styles.cardHeader}>

          <div>
            <p style={styles.sectionLabel}>
              RESOURCE MANAGEMENT
            </p>

            <h2 style={styles.sectionTitle}>
              Usage Summary
            </h2>
          </div>

        </div>

        <div style={styles.usageGrid}>

          {[
            {
              key: "aws_accounts",
              name: "AWS Accounts",
              icon: "AWS",
            },
            {
              key: "team_members",
              name: "Team Members",
              icon: <Users size={17} />,
            },
            {
              key: "scans",
              name: "Scans",
              icon: <Search size={17} />,
            },
            {
              key: "reports",
              name: "Reports",
              icon: <FileText size={17} />,
            },
            {
              key: "storage_mb",
              name: "Storage",
              icon: <HardDrive size={17} />,
              suffix: " MB",
            },
          ].map((item) => {

            const data =
              quotas[item.key] || {};

            const used =
              Number(data.used || 0);

            const limit =
              Number(data.limit || 0);

            const percentage =
              Number(
                data.percentage_used || 0
              );

            return (
              <div
                key={item.key}
                style={styles.usageItem}
              >

                <div style={styles.usageTop}>

                  <span style={styles.usageIcon}>
                    {item.icon}
                  </span>

                  <span style={styles.usageName}>
                    {item.name}
                  </span>

                </div>

                <div style={styles.usageNumbers}>

                  <strong>
                    {used}
                    {item.suffix || ""}
                  </strong>

                  <span>
                    /
                    {data.unlimited
                      ? " Unlimited"
                      : ` ${limit}${item.suffix || ""}`}
                  </span>

                </div>

                <div
                  style={
                    styles.progressBackground
                  }
                >
                  <div
                    style={{
                      ...styles.progressBar,
                      width:
                        data.unlimited
                          ? "8%"
                          : `${Math.min(
                              Math.max(
                                percentage,
                                0
                              ),
                              100
                            )}%`,
                    }}
                  />
                </div>

                <div
                  style={styles.percentage}
                >
                  {data.unlimited
                    ? "Unlimited"
                    : `${percentage}% used`}
                </div>

              </div>
            );
          })}

        </div>

      </section>

      {/* =====================================================
          REMEDIATION GOVERNANCE (STEP 4)
          ====================================================== */}

      <RemediationGovernanceSettings
        organizationId={getOrganizationId()}
        refreshTrigger={refreshKey}
      />

      {/* =====================================================
          SECURITY INFORMATION
          ====================================================== */}

      <section style={styles.securityCard}>

        <div style={styles.securityIcon}>
          ✓
        </div>

        <div>

          <h3 style={styles.securityTitle}>
            SaaS Security
          </h3>

          <p style={styles.securityText}>
            Organization resources are isolated
            using organization-level access control.
            Usage quotas are enforced by the backend
            before protected SaaS operations are
            consumed.
          </p>

        </div>

      </section>

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
    boxSizing: "border-box",
    background:
      "linear-gradient(135deg, #f8fafc 0%, #eef2ff 100%)",
  },

  header: {
    display: "flex",
    justifyContent: "space-between",
    alignItems: "flex-start",
    gap: "20px",
    marginBottom: "28px",
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
    padding: "10px 16px",
    borderRadius: "10px",
    border: "1px solid #cbd5e1",
    background: "#ffffff",
    color: "#334155",
    fontSize: "13px",
    fontWeight: "700",
    cursor: "pointer",
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

  cardHeader: {
    display: "flex",
    justifyContent: "space-between",
    alignItems: "center",
    gap: "15px",
    marginBottom: "22px",
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

  activeBadge: {
    padding: "8px 13px",
    borderRadius: "999px",
    background: "#ecfdf5",
    color: "#047857",
    fontSize: "12px",
    fontWeight: "700",
    textTransform: "capitalize",
  },

  planBadge: {
    padding: "9px 14px",
    borderRadius: "999px",
    background: "#f1f5f9",
    color: "#475569",
    fontSize: "12px",
    fontWeight: "800",
  },

  proBadge: {
    background: "#eef2ff",
    color: "#4338ca",
  },

  infoGrid: {
    display: "grid",
    gridTemplateColumns:
      "repeat(auto-fit, minmax(220px, 1fr))",
    gap: "16px",
  },

  infoItem: {
    padding: "16px",
    borderRadius: "12px",
    background: "#f8fafc",
    border: "1px solid #e2e8f0",
  },

  infoLabel: {
    display: "block",
    marginBottom: "7px",
    fontSize: "11px",
    fontWeight: "700",
    color: "#94a3b8",
    textTransform: "uppercase",
    letterSpacing: "0.6px",
  },

  infoValue: {
    fontSize: "15px",
    color: "#1e293b",
  },

  infoValueSmall: {
    fontSize: "12px",
    color: "#475569",
    wordBreak: "break-all",
  },

  successText: {
    color: "#15803d",
    fontSize: "14px",
  },

  /* =======================================================
     BILLING HERO
     ======================================================= */

  billingHero: {
    display: "flex",
    justifyContent: "space-between",
    alignItems: "center",
    gap: "20px",
    padding: "22px",
    marginBottom: "16px",
    borderRadius: "15px",
    background:
      "linear-gradient(135deg, #eef2ff 0%, #f5f3ff 100%)",
    border: "1px solid #c7d2fe",
  },

  billingHeroLeft: {
    display: "flex",
    alignItems: "center",
    gap: "15px",
  },

  planIcon: {
    width: "48px",
    height: "48px",
    display: "flex",
    alignItems: "center",
    justifyContent: "center",
    borderRadius: "13px",
    background: "#10b981",
    color: "#ffffff",
    fontSize: "21px",
    fontWeight: "800",
    flexShrink: 0,
  },

  currentPlanRow: {
    display: "flex",
    alignItems: "center",
    gap: "10px",
  },

  currentPlanName: {
    margin: "0 0 5px 0",
    fontSize: "25px",
    fontWeight: "800",
    color: "#111827",
  },

  activePlanBadge: {
    marginBottom: "5px",
    padding: "4px 8px",
    borderRadius: "999px",
    background: "#dcfce7",
    color: "#15803d",
    fontSize: "9px",
    fontWeight: "800",
    letterSpacing: "0.5px",
  },

  priceBox: {
    display: "flex",
    alignItems: "baseline",
    flexShrink: 0,
  },

  price: {
    fontSize: "27px",
    fontWeight: "900",
    color: "#312e81",
  },

  pricePeriod: {
    marginLeft: "3px",
    fontSize: "12px",
    color: "#64748b",
  },

  subscriptionGrid: {
    display: "grid",
    gridTemplateColumns:
      "repeat(auto-fit, minmax(220px, 1fr))",
    gap: "16px",
  },

  planBox: {
    padding: "18px",
    borderRadius: "13px",
    background: "#f8fafc",
    border: "1px solid #e2e8f0",
  },

  planText: {
    margin: 0,
    fontSize: "12px",
    lineHeight: "1.5",
    color: "#64748b",
  },

  subscriptionStatus: {
    margin: "4px 0 5px 0",
    fontSize: "18px",
    fontWeight: "800",
    textTransform: "capitalize",
  },

  billingText: {
    margin: "4px 0 5px 0",
    fontSize: "17px",
    fontWeight: "800",
    color: "#334155",
    textTransform: "capitalize",
  },

  periodBox: {
    display: "flex",
    justifyContent: "space-between",
    alignItems: "center",
    gap: "15px",
    marginTop: "16px",
    padding: "15px 17px",
    borderRadius: "12px",
    background: "#f8fafc",
    border: "1px solid #e2e8f0",
  },

  periodValue: {
    display: "block",
    fontSize: "13px",
    color: "#334155",
  },

  cancelBadge: {
    padding: "7px 10px",
    borderRadius: "8px",
    background: "#fff7ed",
    color: "#c2410c",
    fontSize: "11px",
    fontWeight: "700",
  },

  /* =======================================================
     BILLING ACTIONS
     ======================================================= */

  billingActions: {
    marginTop: "20px",
    display: "flex",
    flexDirection: "column",
    alignItems: "flex-start",
    gap: "9px",
  },

  upgradeButton: {
    padding: "13px 21px",
    border: "none",
    borderRadius: "10px",
    background:
      "linear-gradient(135deg, #10b981, #34d399)",
    color: "#ffffff",
    fontSize: "13px",
    fontWeight: "800",
    boxShadow:
      "0 6px 15px rgba(79, 70, 229, 0.2)",
  },

  currentPlanMessage: {
    display: "flex",
    alignItems: "flex-start",
    gap: "11px",
    width: "100%",
    boxSizing: "border-box",
    padding: "13px 15px",
    borderRadius: "10px",
    background: "#f0fdf4",
    border: "1px solid #bbf7d0",
    color: "#166534",
  },

  currentPlanCheck: {
    display: "flex",
    alignItems: "center",
    justifyContent: "center",
    width: "24px",
    height: "24px",
    borderRadius: "50%",
    background: "#22c55e",
    color: "#ffffff",
    fontSize: "13px",
    fontWeight: "900",
    flexShrink: 0,
  },

  billingNote: {
    margin: 0,
    fontSize: "11px",
    color: "#64748b",
  },

  checkoutSuccess: {
    width: "100%",
    boxSizing: "border-box",
    padding: "11px 13px",
    borderRadius: "9px",
    background: "#f0fdf4",
    border: "1px solid #bbf7d0",
    color: "#15803d",
    fontSize: "12px",
    fontWeight: "700",
  },

  checkoutError: {
    width: "100%",
    boxSizing: "border-box",
    padding: "11px 13px",
    borderRadius: "9px",
    background: "#fef2f2",
    border: "1px solid #fecaca",
    color: "#dc2626",
    fontSize: "12px",
    fontWeight: "600",
  },

  /* =======================================================
     TRIAL
     ======================================================= */

  trialBox: {
    display: "grid",
    gridTemplateColumns:
      "repeat(auto-fit, minmax(180px, 1fr))",
    gap: "16px",
    padding: "18px",
    borderRadius: "13px",
    background: "#f8fafc",
    border: "1px solid #e2e8f0",
  },

  trialTitle: {
    margin: 0,
    fontSize: "18px",
    color: "#15803d",
    textTransform: "capitalize",
  },

  trialDays: {
    margin: 0,
    fontSize: "18px",
    color: "#34d399",
  },

  trialEnd: {
    margin: 0,
    fontSize: "16px",
    color: "#334155",
  },

  /* =======================================================
     USAGE
     ======================================================= */

  usageGrid: {
    display: "grid",
    gridTemplateColumns:
      "repeat(auto-fit, minmax(210px, 1fr))",
    gap: "15px",
  },

  usageItem: {
    padding: "17px",
    borderRadius: "13px",
    background: "#f8fafc",
    border: "1px solid #e2e8f0",
  },

  usageTop: {
    display: "flex",
    alignItems: "center",
    gap: "9px",
  },

  usageIcon: {
    fontSize: "18px",
  },

  usageName: {
    fontSize: "13px",
    fontWeight: "700",
    color: "#334155",
  },

  usageNumbers: {
    display: "flex",
    alignItems: "baseline",
    gap: "4px",
    marginTop: "16px",
  },

  progressBackground: {
    height: "7px",
    marginTop: "12px",
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

  percentage: {
    marginTop: "8px",
    fontSize: "11px",
    color: "#64748b",
  },

  /* =======================================================
     SECURITY
     ======================================================= */

  securityCard: {
    display: "flex",
    alignItems: "flex-start",
    gap: "13px",
    padding: "20px",
    borderRadius: "15px",
    border: "1px solid #dbeafe",
    background: "#ffffff",
  },

  securityIcon: {
    width: "38px",
    height: "38px",
    display: "flex",
    alignItems: "center",
    justifyContent: "center",
    flexShrink: 0,
    borderRadius: "50%",
    background: "#dcfce7",
    color: "#15803d",
    fontWeight: "800",
    fontSize: "18px",
  },

  securityTitle: {
    margin: "2px 0 5px 0",
    fontSize: "15px",
    fontWeight: "800",
    color: "#1e3a8a",
  },

  securityText: {
    margin: 0,
    fontSize: "13px",
    lineHeight: "1.6",
    color: "#64748b",
  },

  /* =======================================================
     LOADING
     ======================================================= */

  loading: {
    minHeight: "450px",
    display: "flex",
    flexDirection: "column",
    alignItems: "center",
    justifyContent: "center",
    color: "#64748b",
  },

  spinner: {
    width: "35px",
    height: "35px",
    marginBottom: "14px",
    border: "4px solid #e2e8f0",
    borderTop: "4px solid #10b981",
    borderRadius: "50%",
    animation: "spin 1s linear infinite",
  },

  /* =======================================================
     ERROR
     ======================================================= */

  errorCard: {
    maxWidth: "500px",
    margin: "80px auto",
    padding: "30px",
    textAlign: "center",
    background: "#ffffff",
    border: "1px solid #fecaca",
    borderRadius: "16px",
  },

  errorIcon: {
    width: "42px",
    height: "42px",
    display: "flex",
    alignItems: "center",
    justifyContent: "center",
    margin: "0 auto 12px auto",
    borderRadius: "50%",
    background: "#fee2e2",
    color: "#dc2626",
    fontWeight: "800",
  },

  retryButton: {
    padding: "10px 18px",
    border: "none",
    borderRadius: "9px",
    background: "#10b981",
    color: "#ffffff",
    fontWeight: "700",
    cursor: "pointer",
  },

};

export default Settings;