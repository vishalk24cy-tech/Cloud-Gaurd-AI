import { useState } from "react";
import { Cloud } from "lucide-react";
import { connectAWS } from "../services/awsService";
import "./ConnectAWS.css";

function ConnectAWS() {

  const [formData, setFormData] = useState({
    account_name: "",
    aws_account_id: "",
    role_arn: "",
    region: "ap-south-1",
  });

  const [loading, setLoading] = useState(false);
  const [message, setMessage] = useState("");
  const [error, setError] = useState("");


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
  // CONNECT AWS ACCOUNT
  // ==========================================================

  const handleConnectAWS = async (e) => {

    e.preventDefault();

    setLoading(true);
    setMessage("");
    setError("");


    try {

      const response = await connectAWS(formData);

      setMessage(
        response?.message ||
        "AWS account connected successfully."
      );

      resetForm();

    } catch (err) {

      console.error(
        "AWS connection failed:",
        err
      );

      const backendError =
        err.response?.data?.detail;

      if (Array.isArray(backendError)) {

        setError(
          backendError
            .map((item) => item.msg)
            .join(", ")
        );

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
          Securely connect your AWS account to scan
          cloud resources and receive AI-powered
          security recommendations.
        </p>


        {/* ================================================== */}
        {/* SUCCESS MESSAGE */}
        {/* ================================================== */}

        {message && (

          <div className="success-box">
            ✅ {message}
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

          <label>
            Account Name
          </label>

          <input
            type="text"
            name="account_name"
            placeholder="Production AWS"
            value={formData.account_name}
            onChange={handleChange}
            disabled={loading}
            required
          />


          {/* AWS ACCOUNT ID */}

          <label>
            AWS Account ID
          </label>

          <input
            type="text"
            name="aws_account_id"
            placeholder="123456789012"
            value={formData.aws_account_id}
            onChange={handleChange}
            disabled={loading}
            required
          />


          {/* ROLE ARN */}

          <label>
            Role ARN
          </label>

          <input
            type="text"
            name="role_arn"
            placeholder="arn:aws:iam::123456789012:role/CloudGuardAI-Scanner"
            value={formData.role_arn}
            onChange={handleChange}
            disabled={loading}
            required
          />


          {/* REGION */}

          <label>
            Region
          </label>

          <select
            name="region"
            value={formData.region}
            onChange={handleChange}
            disabled={loading}
          >

            <option value="ap-south-1">
              Asia Pacific (Mumbai)
            </option>

            <option value="us-east-1">
              US East (N. Virginia)
            </option>

            <option value="us-west-2">
              US West (Oregon)
            </option>

            <option value="eu-west-1">
              Europe (Ireland)
            </option>

            <option value="ap-southeast-1">
              Asia Pacific (Singapore)
            </option>

          </select>


          {/* CONNECT BUTTON */}

          <button
            type="submit"
            disabled={loading}
          >

            {loading
              ? "Connecting..."
              : "Connect AWS"}

          </button>

        </form>

      </div>

    </div>

  );

}

export default ConnectAWS;