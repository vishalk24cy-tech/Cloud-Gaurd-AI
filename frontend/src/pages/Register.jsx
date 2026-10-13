import { useState } from "react";
import { Link, useNavigate } from "react-router-dom";
import { ArrowRight, Cloud, Eye, EyeOff, LockKeyhole, Mail, Server, ShieldCheck, UserRound } from "lucide-react";
import api from "../services/api";
import "./Register.css";

function Register() {

  const navigate = useNavigate();

  const [name, setName] = useState("");
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [organization, setOrganization] = useState("");
  const [loading, setLoading] = useState(false);
  const [toast, setToast] = useState(null);
  const [showPassword, setShowPassword] = useState(false);

  const passwordStrength = password.length >= 12 && /[A-Z]/.test(password) && /\d/.test(password)
    ? "Strong"
    : password.length >= 8
      ? "Fair"
      : password.length > 0
        ? "Weak"
        : "";

  const showToast = (type, message) => {
    setToast({ type, message });
    setTimeout(() => setToast(null), 3500);
  };

  const registerUser = async () => {

    if (!name.trim() || !email.trim() || !password.trim()) {
      showToast("error", "Please fill all required fields.");
      return;
    }

    setLoading(true);

    try {

      const response = await api.post("/auth/register", {
        name: name.trim(),
        email: email.trim(),
        password: password.trim(),
        organization: organization.trim()
      });

      console.log(response.data);

      showToast("success", "Registration Successful");

      setTimeout(() => navigate("/"), 800);

    } catch (err) {

      console.log("========== REGISTER ERROR ==========");

      if (err.response) {
        console.log("Status :", err.response.status);
        console.log("Data :", err.response.data);

        if (err.response.status === 400 && err.response.data.detail) {
          showToast("error", err.response.data.detail);
        } else if (err.response.status === 422) {
          showToast("error", "Please fill all required fields correctly.");
        } else {
          showToast("error", err.response.data.detail || "Registration Failed");
        }
      } else {
        console.log(err);
        showToast("error", "Unable to connect to backend.");
      }

    } finally {
      setLoading(false);
    }

  };

  const handleKeyDown = (e) => {
    if (e.key === "Enter") registerUser();
  };

  return (

    <div className="auth-page">
      <header className="auth-site-header">
        <div className="auth-site-brand"><span className="auth-site-mark"><ShieldCheck size={19} /></span><span>CloudGuard<span>AI</span></span></div>
        <nav className="auth-site-nav" aria-label="Product navigation"><span>Product</span><span>Features</span><span>Pricing</span><span>Resources</span><span>Company</span></nav>
        <div className="auth-site-actions"><button type="button" className="auth-outline-action" onClick={() => navigate("/")}>Sign In</button><span className="auth-current-link">Get Started</span></div>
      </header>

      {/* Toast */}
      {toast && (
        <div className={`auth-toast ${toast.type}`}>
          <span>{toast.type === "success" ? "✓" : "✕"}</span>
          {toast.message}
        </div>
      )}

      <main className="auth-hero">
        <section className="auth-hero-content">
          <span className="auth-hero-badge">AI-POWERED CLOUD SECURITY</span>
          <h1>Secure your cloud<br /><em>with confidence</em></h1>
          <p className="auth-hero-description">Detect, prioritize, and fix security risks across your AWS environment with AI-powered threat intelligence and continuous monitoring.</p>
          <div className="auth-feature-grid">
            <div><Cloud size={17} /><strong>Cloud visibility</strong><span>Across connected resources</span></div>
            <div><ShieldCheck size={17} /><strong>AI threat intelligence</strong><span>Security analysis and risk insights</span></div>
            <div><Server size={17} /><strong>Continuous monitoring</strong><span>Real-time security visibility</span></div>
            <div><LockKeyhole size={17} /><strong>Risk management</strong><span>Clear security posture signals</span></div>
          </div>
          <div className="auth-infrastructure" aria-hidden="true">
            <div className="infra-label infra-monitor">Monitor</div><div className="infra-label infra-detect">Detect</div><div className="infra-label infra-protect">Protect</div>
            <div className="infra-cloud"><Cloud size={31} /><span>AWS CLOUD</span></div><div className="infra-line infra-line-one" /><div className="infra-line infra-line-two" />
            <div className="infra-node infra-node-one"><Server size={16} /><span>EC2</span></div><div className="infra-node infra-node-two"><ShieldCheck size={16} /><span>IAM</span></div><div className="infra-node infra-node-three"><Cloud size={16} /><span>S3</span></div>
          </div>
          <div className="auth-capabilities"><span><strong>AWS SECURITY</strong>Cloud monitoring</span><span><strong>AI ANALYSIS</strong>Security intelligence</span><span><strong>CONTINUOUS VISIBILITY</strong>Posture management</span></div>
        </section>

      <section className="auth-card animate-in">

        <div className="auth-logo">
          <div className="shield-icon"><ShieldCheck size={25} /></div>
          <h1>Create your secure workspace</h1>
          <p>Join the CloudGuardAI security platform</p>
        </div>

        <div className="auth-form">

          <div className="input-group animate-in delay-1">
            <label htmlFor="register-name"><UserRound size={14} /> Full Name</label>
            <input
              id="register-name"
              type="text"
              placeholder="Your full name"
              value={name}
              onChange={(e) => setName(e.target.value)}
              onKeyDown={handleKeyDown}
            />
          </div>

          <div className="input-group animate-in delay-2">
            <label htmlFor="register-email"><Mail size={14} /> Email</label>
            <input
              id="register-email"
              type="email"
              placeholder="you@company.com"
              value={email}
              onChange={(e) => setEmail(e.target.value)}
              onKeyDown={handleKeyDown}
            />
          </div>

          <div className="input-group animate-in delay-3">
            <label htmlFor="register-password"><LockKeyhole size={14} /> Password</label>
            <div className="register-password-field">
            <input
              id="register-password"
              type={showPassword ? "text" : "password"}
              placeholder="Create a strong password"
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              onKeyDown={handleKeyDown}
            />
            <button type="button" aria-label={showPassword ? "Hide password" : "Show password"} onClick={() => setShowPassword((visible) => !visible)}>
              {showPassword ? <EyeOff size={16} /> : <Eye size={16} />}
            </button>
            </div>
            {passwordStrength && <div className={`password-strength ${passwordStrength.toLowerCase()}`}><span /><span /><span /><strong>{passwordStrength}</strong></div>}
          </div>

          <div className="input-group animate-in delay-4">
            <label htmlFor="register-organization"><Cloud size={14} /> Organization <span style={{opacity: 0.5, fontWeight: 400, textTransform: 'none'}}>(optional)</span></label>
            <input
              id="register-organization"
              type="text"
              placeholder="Your organization"
              value={organization}
              onChange={(e) => setOrganization(e.target.value)}
              onKeyDown={handleKeyDown}
            />
          </div>

          <button
            className={`auth-btn register-btn animate-in delay-5 ${loading ? "loading" : ""}`}
            onClick={registerUser}
            disabled={loading}
          >
            {loading ? (
              <span className="btn-spinner" />
            ) : (
              <>Create Account <ArrowRight size={16} /></>
            )}
          </button>

          <p className="auth-link animate-in delay-6">
            Already have an account?{" "}
            <Link to="/">Sign In</Link>
          </p>

        </div>

      </section>
      </main>

    </div>
  );

}

export default Register;