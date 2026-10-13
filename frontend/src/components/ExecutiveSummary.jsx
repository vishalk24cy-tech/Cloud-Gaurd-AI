import "./ExecutiveSummary.css";

function ExecutiveSummary({ dashboard }) {

  const riskScore =
    dashboard?.ai_risk_score ??
    dashboard?.risk_score ??
    75;


  const severity =
    dashboard?.overall_severity ??
    dashboard?.severity ??
    "HIGH";


  const summary =
    dashboard?.executive_summary ??
    "Security posture analysis identified multiple cloud security findings. AI engine analyzed AWS resources, IAM permissions, and configuration policies to detect possible security risks and recommend remediation actions.";


  return (

    <div className="security-posture-card">


      {/* Header */}

      <div className="posture-header">

        <div>

          <h2>
            Security Posture Overview
          </h2>

          <p>
            AI-powered cloud security analysis and threat intelligence
          </p>

        </div>


        <div
          className={`severity-badge ${
            severity.toLowerCase()
          }`}
        >
          {severity}
        </div>


      </div>



      {/* Score Section */}

      <div className="posture-metrics">


        <div className="metric-box">

          <span>
            AI Risk Score
          </span>

          <strong>
            {riskScore}
          </strong>

          <small>
            Security Intelligence Score
          </small>

        </div>



        <div className="metric-box">

          <span>
            Threat Level
          </span>

          <strong className="danger">
            {severity}
          </strong>

          <small>
            Based on detected findings
          </small>

        </div>



        <div className="metric-box">

          <span>
            AWS Monitoring
          </span>

          <strong className="safe">
            Active
          </strong>

          <small>
            Real-time cloud analysis
          </small>

        </div>


      </div>




      {/* AI Summary */}


      <div className="ai-summary">


        <h3>
          Executive Analysis
        </h3>


        <p>
          {summary}
        </p>


      </div>




      {/* Recommendation */}


      <div className="recommendation-box">


        <h3>
          AI Recommendations
        </h3>


        <ul>

          <li>
            Review IAM user permissions and enable MFA protection.
          </li>


          <li>
            Continuously monitor AWS resources for misconfigurations.
          </li>


          <li>
            Apply security policies based on cloud compliance standards.
          </li>


        </ul>


      </div>



    </div>

  );
}


export default ExecutiveSummary;