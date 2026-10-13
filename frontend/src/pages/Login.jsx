import { useState } from "react";
import { useNavigate } from "react-router-dom";
import { ArrowRight, Cloud, Eye, EyeOff, LockKeyhole, Mail, Server, ShieldCheck, TriangleAlert } from "lucide-react";
import api from "../services/api";
import "./Login.css";

function Login() {
  const navigate = useNavigate();
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState("");
  const [showPassword, setShowPassword] = useState(false);

  const handleLogin = async (e) => {
    e.preventDefault();

    setError("");
    setLoading(true);

    try {
      const response = await api.post("/auth/login", {
        email: email,
        password: password,
      });

      console.log("LOGIN RESPONSE:", response.data);

      // Get JWT token
      const token =
        response.data.token ||
        response.data.access_token;

      if (!token) {
        console.error("Token not found:", response.data);

        setError(
          "Login successful, but authentication token was not received."
        );

        return;
      }

      // Save JWT token
      localStorage.setItem("token", token);

      // Save user information
      if (response.data.user) {
        localStorage.setItem(
          "user",
          JSON.stringify(response.data.user)
        );
      }

      console.log("TOKEN SAVED SUCCESSFULLY");

      // Go to dashboard
      navigate("/dashboard");

    } catch (err) {
      console.error("LOGIN ERROR:", err);

      setError(
        err.response?.data?.detail ||
        err.response?.data?.message ||
        "Invalid email or password"
      );

    } finally {
      setLoading(false);
    }
  };

  const goToRegister = () => {
    navigate("/register");
  };

  return (
    <div className="login-page">
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
            <div className="security-wave security-wave-one" />
            <div className="security-wave security-wave-two" />
            <div className="infra-label infra-monitor">Monitor</div>
            <div className="infra-label infra-detect">Detect</div>
            <div className="infra-label infra-protect">Protect</div>
            <div className="infra-cloud"><Cloud size={31} /><span>AWS CLOUD</span></div>
            <div className="infra-line infra-line-one" /><div className="infra-line infra-line-two" /><div className="infra-line infra-line-three" />
            <div className="infra-node infra-node-one"><Server size={16} /><span>EC2</span></div>
            <div className="infra-node infra-node-two"><ShieldCheck size={16} /><span>IAM</span></div>
            <div className="infra-node infra-node-three"><Cloud size={16} /><span>S3</span></div>
            <div className="infra-security-node infra-security-one"><ShieldCheck size={11} /></div>
            <div className="infra-security-node infra-security-two"><LockKeyhole size={11} /></div>
            <div className="infra-security-node infra-security-three"><ShieldCheck size={11} /></div>
          </div>

          <div className="auth-capabilities"><span><strong>AWS SECURITY</strong>Cloud monitoring</span><span><strong>AI ANALYSIS</strong>Security intelligence</span><span><strong>CONTINUOUS VISIBILITY</strong>Posture management</span></div>
        </section>

        <section className="login-card">
          <div className="login-brand">
            <div className="brand-logo"><ShieldCheck size={22} /></div>
            <div className="brand-content"><div className="brand-name">Cloud<span>GuardAI</span></div><div className="brand-subtitle">Cloud Security Platform</div></div>
          </div>

        {/* SECURITY ICON */}
        <div className="login-security-icon">
          <LockKeyhole size={25} />
        </div>


        {/* HEADER */}
        <div className="login-header">

          <h1>
            Sign in to CloudGuardAI
          </h1>

          <p>
            Access your cloud security dashboard
          </p>

        </div>


        {/* ERROR */}
        {error && (
          <div className="login-error">

            <TriangleAlert size={16} />

            <span>
              {error}
            </span>

          </div>
        )}


        {/* FORM */}
        <form onSubmit={handleLogin}>


          {/* EMAIL */}
          <div className="login-field">

            <label htmlFor="email">
              Email
            </label>

            <div className="login-input-wrapper">

              <span className="login-input-icon">
                <Mail size={16} />
              </span>

              <input
                id="email"
                type="email"
                placeholder="Enter your email"
                value={email}
                onChange={(e) => setEmail(e.target.value)}
                autoComplete="email"
                required
              />

            </div>

          </div>


          {/* PASSWORD */}
          <div className="login-field">

            <div className="password-label-row">

              <label htmlFor="password">
                Password
              </label>

              <button
                type="button"
                className="forgot-password"
                onClick={() =>
                  alert("Password reset feature coming soon")
                }
              >
                Forgot password?
              </button>

            </div>


            <div className="login-input-wrapper">

              <span className="login-input-icon">
                <LockKeyhole size={16} />
              </span>

              <input
                id="password"
                type={showPassword ? "text" : "password"}
                placeholder="Enter your password"
                value={password}
                onChange={(e) => setPassword(e.target.value)}
                autoComplete="current-password"
                required
              />

              <button
                type="button"
                className="password-eye"
                aria-label={showPassword ? "Hide password" : "Show password"}
                onClick={() => setShowPassword((visible) => !visible)}
              >
                {showPassword ? <EyeOff size={16} /> : <Eye size={16} />}
              </button>

            </div>

          </div>


          {/* REMEMBER ME */}
          <div className="remember-container">

            <label className="remember-label">

              <input
                type="checkbox"
              />

              <span>
                Keep me signed in
              </span>

            </label>

          </div>


          {/* LOGIN BUTTON */}
          <button
            type="submit"
            className="login-button"
            disabled={loading}
          >

            {loading ? (
              <>
                <span className="login-spinner"></span>

                Signing in...
              </>
            ) : (
              <>
                <span>
                  Sign In
                </span>

                <span className="button-arrow">
                  <ArrowRight size={17} />
                </span>
              </>
            )}

          </button>

        </form>


        {/* REGISTER */}
        <div className="register-section">

          <span>
            New to CloudGuardAI?
          </span>

          <button
            type="button"
            onClick={goToRegister}
          >
            Create an account
          </button>

        </div>


        {/* SECURITY STATUS */}
        <div className="security-status">

          <div className="security-item">

            <span className="security-icon">
              <ShieldCheck size={14} />
            </span>

            <span>
              Secure connection
            </span>

          </div>


          <div className="security-divider"></div>


          <div className="security-item">

            <span className="security-icon">
              <LockKeyhole size={14} />
            </span>

            <span>
              Your data is protected
            </span>

          </div>

        </div>

      </section>


      {/* FOOTER */}
      <div className="login-footer">

        <span>
          CloudGuardAI
        </span>

        <span className="footer-dot">
          •
        </span>

        <span>
          Cloud Security Operations
        </span>

      </div>
      </main>

    </div>
  );
}

export default Login;