import { useState, useEffect } from "react";
import { Cloud, Copy, Check, ShieldCheck } from "lucide-react";
import { connectAWS, getAWSSetupIntent, testAWSConnection } from "../services/awsService";
import "./ConnectAWS.css";

function ConnectAWS() {

  const [formData, setFormData] = useState({
    account_name: "",
    aws_account_id: "",
    role_arn: "",
    region: "ap-south-1",
  });

  const [setupIntent, setSetupIntent] = useState(null);
  const [copied, setCopied] = useState(false);
  const [loading, setLoading] = useState(false);
  const [verifying, setVerifying] = useState(false);
  const [message, setMessage] = useState("");
  const [error, setError] = useState("");

  // ==========================================================
  // FETCH SECURE SETUP INTENT & EXTERNAL ID
  // ==========================================================

  useEffect(() => {
    let isMounted = true;
    async function loadSetupIntent() {
      try {
        const data = await getAWSSetupIntent();
        if (isMounted && data) {
          setSetupIntent(data);
        }
      } catch (err) {
        console.warn("Could not pre-fetch setup intent:", err);
      }
    }
    loadSetupIntent();
    return () => {
      isMounted = false;
    };
  }, []);

  const copyExternalId = () => {
    if (setupIntent?.external_id) {
      navigator.clipboard.writeText(setupIntent.external_id);
      setCopied(true);
      setTimeout(() => setCopied(false), 2000);
    }
  };

  // ==========================================================
  // HANDLE INPUT CHANGE
  // ==========================================================

  const handleChange = (e) => {
    const { name, value } = e.target;
    setFormData((previous) => ({
      ...previous,
      [name]: value,
    }));
  };

  // ==========================================================
  // RESET FORM
  // ==========================================================

  const resetForm = () => {
    setFormData({
      account_name: "",
      aws_account_id: "",
      role_arn: "",
      region: "ap-south-1",
    });
  };

  // ==========================================================
  // CONNECT & VERIFY AWS ACCOUNT
  // ==========================================================

  const handleConnectAWS = async (e) => {
    e.preventDefault();
    setLoading(true);
    setMessage("");
    setError("");

    try {
      const payload = { ...formData };
      if (setupIntent?.external_id) {
        payload.external_id = setupIntent.external_id;
      }

      const response = await connectAWS(payload);
      const newAccount = response?.account;

      if (newAccount?._id) {
        setMessage("Account registered. Performing STS pre-flight verification...");
        setVerifying(true);
        try {
          await testAWSConnection(newAccount._id);
          setMessage("✅ AWS Account Connected and Verified Successfully!");
          resetForm();
        } catch (verifyErr) {
          const verifyMsg =
            verifyErr.response?.data?.detail ||
            verifyErr.response?.data?.message ||
            "Verification handshake failed.";
          setError(
            `Account registered, but pre-flight STS verification failed: ${verifyMsg}. Please check your IAM role trust policy and ExternalId.`
          );
        } finally {
          setVerifying(false);
        }
      } else {
        setMessage(
          response?.message || "AWS account connected successfully."
        );
        resetForm();
      }
    } catch (err) {
      console.error("AWS connection failed:", err);
      const backendError = err.response?.data?.detail;
      if (Array.isArray(backendError)) {
        setError(backendError.map((item) => item.msg).join(", "));
      } else {
        setError(
          backendError ||
          "Unable to connect AWS account. Please check the details and try again."
        );
      }
    } finally {
      setLoading(false);
    }
  };

  // ==========================================================
  // UI
  // ==========================================================

  return (
    <div className="connect-page">
      <div className="connect-card">
        <h1>
          <Cloud size={22} /> Connect AWS Account
        </h1>

        <p>
          Securely connect your AWS account to scan cloud resources and receive AI-powered
          security recommendations with Confused Deputy defense.
        </p>

        {/* ================================================== */}
        {/* SECURE EXTERNAL ID SETUP INSTRUCTIONS */}
        {/* ================================================== */}

        {setupIntent?.external_id && (
          <div
            className="setup-intent-card"
            style={{
              background: "rgba(16, 185, 129, 0.06)",
              border: "1px solid rgba(16, 185, 129, 0.25)",
              borderRadius: "10px",
              padding: "16px",
              marginBottom: "20px",
            }}
          >
            <div
              style={{
                display: "flex",
                alignItems: "center",
                justifyContent: "space-between",
                marginBottom: "8px",
              }}
            >
              <div
                style={{
                  display: "flex",
                  alignItems: "center",
                  gap: "8px",
                  fontWeight: "600",
                  color: "var(--accent-bright)",
                }}
              >
                <ShieldCheck size={18} />
                <span>Required IAM Role ExternalId (Confused Deputy Protection)</span>
              </div>
              <button
                type="button"
                onClick={copyExternalId}
                style={{
                  display: "inline-flex",
                  alignItems: "center",
                  gap: "6px",
                  padding: "4px 10px",
                  fontSize: "12px",
                  fontWeight: "600",
                  background: copied ? "rgba(16, 185, 129, 0.3)" : "rgba(255, 255, 255, 0.08)",
                  color: "var(--text-bright)",
                  border: "1px solid rgba(255, 255, 255, 0.15)",
                  borderRadius: "6px",
                  cursor: "pointer",
                }}
              >
                {copied ? <Check size={14} /> : <Copy size={14} />}
                <span>{copied ? "Copied" : "Copy"}</span>
              </button>
            </div>
            <code
              style={{
                display: "block",
                background: "rgba(0, 0, 0, 0.35)",
                padding: "8px 12px",
                borderRadius: "6px",
                fontSize: "12px",
                color: "#34d399",
                fontFamily: "monospace",
                wordBreak: "break-all",
                marginBottom: "8px",
              }}
            >
              {setupIntent.external_id}
            </code>
            <p
              style={{
                margin: 0,
                fontSize: "12px",
                color: "var(--text-muted)",
                lineHeight: "1.4",
              }}
            >
              Configure your AWS IAM Role trust policy condition with:
              <strong style={{ color: "var(--text-bright)", marginLeft: "4px" }}>
                sts:ExternalId = &quot;{setupIntent.external_id}&quot;
              </strong>
            </p>
          </div>
        )}

        {/* ================================================== */}
        {/* SUCCESS MESSAGE */}
        {/* ================================================== */}

        {message && (
          <div className="success-box">
            {message}
          </div>
        )}

        {/* ================================================== */}
        {/* ERROR MESSAGE */}
        {/* ================================================== */}

        {error && (
          <div className="error-box">
            ❌ {error}
          </div>
        )}

        {/* ================================================== */}
        {/* AWS CONNECTION FORM */}
        {/* ================================================== */}

        <form onSubmit={handleConnectAWS}>
          {/* ACCOUNT NAME */}
          <label>Account Name</label>
          <input
            type="text"
            name="account_name"
            placeholder="Production AWS"
            value={formData.account_name}
            onChange={handleChange}
            disabled={loading || verifying}
            required
          />

          {/* AWS ACCOUNT ID */}
          <label>AWS Account ID</label>
          <input
            type="text"
            name="aws_account_id"
            placeholder="123456789012"
            value={formData.aws_account_id}
            onChange={handleChange}
            disabled={loading || verifying}
            required
          />

          {/* ROLE ARN */}
          <label>Role ARN</label>
          <input
            type="text"
            name="role_arn"
            placeholder="arn:aws:iam::123456789012:role/CloudGuardAI-Scanner"
            value={formData.role_arn}
            onChange={handleChange}
            disabled={loading || verifying}
            required
          />

          {/* REGION */}
          <label>Region</label>
          <select
            name="region"
            value={formData.region}
            onChange={handleChange}
            disabled={loading || verifying}
          >
            <option value="ap-south-1">Asia Pacific (Mumbai)</option>
            <option value="us-east-1">US East (N. Virginia)</option>
            <option value="us-west-2">US West (Oregon)</option>
            <option value="eu-west-1">Europe (Ireland)</option>
            <option value="ap-southeast-1">Asia Pacific (Singapore)</option>
          </select>

          {/* CONNECT BUTTON */}
          <button
            type="submit"
            disabled={loading || verifying}
          >
            {loading || verifying
              ? (verifying ? "Verifying STS Connection..." : "Connecting...")
              : "Connect & Verify AWS Account"}
          </button>
        </form>
      </div>
    </div>
  );
}

export default ConnectAWS;
