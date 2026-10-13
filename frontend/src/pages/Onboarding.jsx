import {
  useEffect,
  useState,
} from "react";

import {
  useNavigate,
} from "react-router-dom";

import api from "../services/api";


/* =========================================================
   ONBOARDING PAGE
   ========================================================= */

function Onboarding() {

  const navigate = useNavigate();

  const [loading, setLoading] =
    useState(true);

  const [error, setError] =
    useState("");

  const [onboarding, setOnboarding] =
    useState(null);


  /* =========================================================
     GET ORGANIZATION ID
     ========================================================= */

  const getOrganizationId = () => {

    try {

      const user =
        JSON.parse(
          localStorage.getItem("user") ||
          "{}"
        );

      return (
        user?.organization ||
        user?.organization_id ||
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


  /* =========================================================
     LOAD ONBOARDING STATUS
     ========================================================= */

  const loadOnboarding = async () => {

    try {

      setLoading(true);
      setError("");

      const organizationId =
        getOrganizationId();


      if (!organizationId) {

        throw new Error(
          "Organization ID not found."
        );

      }


      const response =
        await api.get(
          `/organizations/${organizationId}/onboarding`
        );


      setOnboarding(
        response.data
      );

    } catch (error) {

      console.error(
        "Onboarding loading error:",
        error
      );

      setError(
        error?.response?.data?.detail ||
        error?.message ||
        "Unable to load onboarding status."
      );

    } finally {

      setLoading(false);

    }

  };


  /* =========================================================
     INITIAL LOAD
     ========================================================= */

  useEffect(() => {

    loadOnboarding();

  }, []);


  /* =========================================================
     CONTINUE TO NEXT STEP
     ========================================================= */

  const continueToNextStep = () => {

    if (!onboarding) {

      return;

    }


    const steps =
      onboarding.steps || {};


    /* -------------------------------------------------------
       PLAN
       ------------------------------------------------------- */

    if (!steps.plan_selected) {

      navigate("/settings");

      return;

    }


    /* -------------------------------------------------------
       TEAM
       ------------------------------------------------------- */

    if (!steps.team_setup) {

      navigate("/team-members");

      return;

    }


    /* -------------------------------------------------------
       AWS
       ------------------------------------------------------- */

    if (!steps.aws_connected) {

      navigate("/connect-aws");

      return;

    }


    /* -------------------------------------------------------
       FIRST SCAN
       ------------------------------------------------------- */

    if (!steps.first_scan_completed) {

      navigate(
        "/dashboard?onboarding=scan"
      );

      return;

    }


    /* -------------------------------------------------------
       ALL STEPS COMPLETE
       ------------------------------------------------------- */

    navigate("/dashboard");

  };


  /* =========================================================
     LOADING SCREEN
     ========================================================= */

  if (loading) {

    return (

      <div style={styles.page}>

        <div style={styles.centerCard}>

          <div style={styles.loadingIcon}>
            ⏳
          </div>

          <h2 style={styles.centerTitle}>
            Loading your workspace
          </h2>

          <p style={styles.centerText}>
            Checking your CloudGuardAI
            onboarding progress...
          </p>

        </div>

      </div>

    );

  }


  /* =========================================================
     ERROR SCREEN
     ========================================================= */

  if (error) {

    return (

      <div style={styles.page}>

        <div style={styles.centerCard}>

          <div style={styles.errorIcon}>
            !
          </div>

          <h2 style={styles.centerTitle}>
            Unable to load onboarding
          </h2>

          <p style={styles.errorText}>
            {error}
          </p>

          <button
            type="button"
            onClick={loadOnboarding}
            style={styles.primaryButton}
          >
            Try Again
          </button>

        </div>

      </div>

    );

  }


  /* =========================================================
     DATA
     ========================================================= */

  const steps =
    onboarding?.steps || {};


  const progress =
    Number(
      onboarding?.progress_percentage || 0
    );


  const completedSteps =
    Number(
      onboarding?.completed_steps || 0
    );


  const totalSteps =
    Number(
      onboarding?.total_steps || 5
    );


  /* =========================================================
     ONBOARDING STEPS
     ========================================================= */

  const stepList = [

    {
      key:
        "organization_created",

      title:
        "Organization created",

      description:
        "Your CloudGuardAI workspace is ready.",
    },


    {
      key:
        "plan_selected",

      title:
        "Choose your plan",

      description:
        "Select the subscription plan for your workspace.",
    },


    {
      key:
        "team_setup",

      title:
        "Set up your team",

      description:
        "Invite teammates and assign appropriate roles.",
    },


    {
      key:
        "aws_connected",

      title:
        "Connect AWS",

      description:
        "Connect an AWS account for security monitoring.",
    },


    {
      key:
        "first_scan_completed",

      title:
        "Run your first security scan",

      description:
        "Scan your AWS environment and discover security findings.",
    },

  ];


  /* =========================================================
     RENDER
     ========================================================= */

  return (

    <div style={styles.page}>

      <div style={styles.container}>


        {/* =================================================
            HEADER
        ================================================== */}

        <div style={styles.header}>

          <div>

            <div style={styles.eyebrow}>
              CLOUDGUARDAI
            </div>

            <h1 style={styles.mainTitle}>
              Welcome to CloudGuardAI
            </h1>

            <p style={styles.subtitle}>
              Let's get your security
              workspace ready.
            </p>

          </div>


          <div style={styles.organizationBox}>

            <span
              style={
                styles.organizationLabel
              }
            >
              Organization
            </span>

            <strong>
              {onboarding?.organization_name ||
                "Your Organization"}
            </strong>

          </div>

        </div>


        {/* =================================================
            PROGRESS CARD
        ================================================== */}

        <div style={styles.progressCard}>

          <div style={styles.progressHeader}>

            <div>

              <h2 style={styles.sectionTitle}>
                Workspace setup
              </h2>

              <p style={styles.progressText}>
                {completedSteps} of{" "}
                {totalSteps} steps completed
              </p>

            </div>


            <div style={styles.progressNumber}>
              {progress}%
            </div>

          </div>


          <div style={styles.progressTrack}>

            <div
              style={{
                ...styles.progressBar,
                width: `${progress}%`,
              }}
            />

          </div>

        </div>


        {/* =================================================
            STEPS
        ================================================== */}

        <div style={styles.stepsCard}>

          <div style={styles.cardHeader}>

            <div>

              <div style={styles.sectionLabel}>
                GET STARTED
              </div>

              <h2 style={styles.sectionTitle}>
                Complete your setup
              </h2>

            </div>

          </div>


          <div>

            {stepList.map(
              (step, index) => {

                const completed =
                  Boolean(
                    steps[step.key]
                  );


                return (

                  <div
                    key={step.key}
                    style={{
                      ...styles.step,

                      borderBottom:
                        index ===
                        stepList.length - 1
                          ? "none"
                          : "1px solid #eef2f7",
                    }}
                  >


                    {/* STEP ICON */}

                    <div
                      style={{
                        ...styles.stepIcon,

                        ...(completed
                          ? styles.stepIconCompleted
                          : {}),
                      }}
                    >

                      {completed
                        ? "✓"
                        : index + 1}

                    </div>


                    {/* STEP CONTENT */}

                    <div
                      style={
                        styles.stepContent
                      }
                    >

                      <div
                        style={
                          styles.stepTitle
                        }
                      >
                        {step.title}
                      </div>

                      <div
                        style={
                          styles.stepDescription
                        }
                      >
                        {step.description}
                      </div>

                    </div>


                    {/* STATUS */}

                    <div
                      style={{
                        ...styles.stepStatus,

                        ...(completed
                          ? styles.completedStatus
                          : styles.pendingStatus),
                      }}
                    >

                      {completed
                        ? "Completed"
                        : "Pending"}

                    </div>

                  </div>

                );

              }
            )}

          </div>

        </div>


        {/* =================================================
            NEXT ACTION
        ================================================== */}

        <div style={styles.actionCard}>

          <div>

            <h2 style={styles.actionTitle}>

              {onboarding?.onboarding_completed

                ? "Your workspace is ready 🎉"

                : "Continue setting up CloudGuardAI"}

            </h2>


            <p style={styles.actionText}>

              {onboarding?.onboarding_completed

                ? "All onboarding steps have been completed."

                : "Complete the next pending step to finish your workspace setup."}

            </p>

          </div>


          <button
            type="button"
            onClick={
              onboarding?.onboarding_completed
                ? () =>
                    navigate("/dashboard")
                : continueToNextStep
            }
            style={styles.primaryButton}
          >

            {onboarding?.onboarding_completed

              ? "Go to Dashboard →"

              : "Continue →"}

          </button>

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
    boxSizing: "border-box",
    background:
      "linear-gradient(135deg, #f8fafc 0%, #eef2ff 100%)",
  },


  container: {
    maxWidth: "1050px",
    margin: "0 auto",
  },


  header: {
    display: "flex",
    justifyContent: "space-between",
    alignItems: "flex-start",
    gap: "25px",
    marginBottom: "28px",
    flexWrap: "wrap",
  },


  eyebrow: {
    marginBottom: "8px",
    fontSize: "11px",
    fontWeight: "800",
    letterSpacing: "1.6px",
    color: "#34d399",
  },


  mainTitle: {
    margin: 0,
    fontSize: "34px",
    fontWeight: "800",
    color: "#111827",
  },


  subtitle: {
    margin:
      "8px 0 0 0",
    fontSize: "14px",
    color: "#64748b",
  },


  organizationBox: {
    minWidth: "200px",
    padding: "16px 20px",
    background: "#ffffff",
    border:
      "1px solid #e2e8f0",
    borderRadius: "13px",
    boxShadow:
      "0 8px 20px rgba(15, 23, 42, 0.05)",
  },


  organizationLabel: {
    display: "block",
    marginBottom: "5px",
    fontSize: "11px",
    fontWeight: "700",
    color: "#94a3b8",
    textTransform: "uppercase",
  },


  progressCard: {
    padding: "24px",
    marginBottom: "20px",
    background: "#ffffff",
    border:
      "1px solid #e2e8f0",
    borderRadius: "17px",
    boxShadow:
      "0 8px 25px rgba(15, 23, 42, 0.05)",
  },


  progressHeader: {
    display: "flex",
    justifyContent: "space-between",
    alignItems: "center",
    gap: "20px",
  },


  sectionLabel: {
    marginBottom: "5px",
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


  progressText: {
    margin:
      "6px 0 0 0",
    fontSize: "13px",
    color: "#64748b",
  },


  progressNumber: {
    fontSize: "28px",
    fontWeight: "800",
    color: "#10b981",
  },


  progressTrack: {
    height: "9px",
    marginTop: "20px",
    overflow: "hidden",
    borderRadius: "999px",
    background: "#e2e8f0",
  },


  progressBar: {
    height: "100%",
    borderRadius: "999px",
    background:
      "linear-gradient(90deg, #10b981, #34d399)",
    transition:
      "width 0.4s ease",
  },


  stepsCard: {
    padding: "24px",
    marginBottom: "20px",
    background: "#ffffff",
    border:
      "1px solid #e2e8f0",
    borderRadius: "17px",
    boxShadow:
      "0 8px 25px rgba(15, 23, 42, 0.05)",
  },


  cardHeader: {
    marginBottom: "5px",
  },


  step: {
    display: "flex",
    alignItems: "center",
    gap: "15px",
    padding: "18px 5px",
  },


  stepIcon: {
    width: "36px",
    height: "36px",
    flexShrink: 0,
    display: "flex",
    alignItems: "center",
    justifyContent: "center",
    borderRadius: "50%",
    background: "#eef2f7",
    color: "#64748b",
    fontSize: "13px",
    fontWeight: "800",
  },


  stepIconCompleted: {
    background: "#dcfce7",
    color: "#15803d",
  },


  stepContent: {
    flex: 1,
    minWidth: 0,
  },


  stepTitle: {
    fontSize: "14px",
    fontWeight: "800",
    color: "#1e293b",
  },


  stepDescription: {
    marginTop: "4px",
    fontSize: "12px",
    lineHeight: "1.5",
    color: "#64748b",
  },


  stepStatus: {
    flexShrink: 0,
    padding:
      "6px 10px",
    borderRadius: "999px",
    fontSize: "11px",
    fontWeight: "800",
  },


  completedStatus: {
    background: "#ecfdf5",
    color: "#047857",
  },


  pendingStatus: {
    background: "#fff7ed",
    color: "#c2410c",
  },


  actionCard: {
    display: "flex",
    alignItems: "center",
    justifyContent: "space-between",
    gap: "20px",
    flexWrap: "wrap",
    padding: "24px",
    background: "#111827",
    borderRadius: "17px",
  },


  actionTitle: {
    margin: 0,
    fontSize: "18px",
    fontWeight: "800",
    color: "#ffffff",
  },


  actionText: {
    margin:
      "6px 0 0 0",
    fontSize: "13px",
    color: "#cbd5e1",
  },


  primaryButton: {
    padding:
      "12px 20px",
    border: "none",
    borderRadius: "10px",
    background: "#10b981",
    color: "#ffffff",
    fontSize: "13px",
    fontWeight: "800",
    cursor: "pointer",
  },


  centerCard: {
    maxWidth: "500px",
    margin: "80px auto",
    padding: "35px",
    textAlign: "center",
    background: "#ffffff",
    border:
      "1px solid #e2e8f0",
    borderRadius: "17px",
    boxShadow:
      "0 8px 25px rgba(15, 23, 42, 0.05)",
  },


  loadingIcon: {
    fontSize: "36px",
    marginBottom: "10px",
  },


  centerTitle: {
    margin:
      "8px 0",
    color: "#111827",
  },


  centerText: {
    margin: 0,
    fontSize: "13px",
    color: "#64748b",
  },


  errorIcon: {
    width: "45px",
    height: "45px",
    margin:
      "0 auto 12px",
    display: "flex",
    alignItems: "center",
    justifyContent: "center",
    borderRadius: "50%",
    background: "#fee2e2",
    color: "#dc2626",
    fontSize: "22px",
    fontWeight: "800",
  },


  errorText: {
    marginBottom: "20px",
    fontSize: "13px",
    color: "#dc2626",
  },

};


export default Onboarding;