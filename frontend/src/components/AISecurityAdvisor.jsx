import { useState } from "react";
import {
  ShieldAlert,
  ChevronDown,
  ChevronUp,
  Copy,
  Check,
  Terminal,
  Code2,
  Lightbulb,
  AlertTriangle,
  Clock,
  Target
} from "lucide-react";

import "./AISecurityAdvisor.css";

function AISecurityAdvisor({ analysis }) {

  const [expanded, setExpanded] = useState(null);

  const [copied, setCopied] = useState(null);


  // ==========================================
  // NO AI ANALYSIS
  // ==========================================

  if (!analysis) {

    return (

      <div className="ai-card ai-empty">

        <div className="ai-empty-icon">

          <ShieldAlert size={28} />

        </div>

        <div>

          <h2>
            CloudGuardAI Security Analyst
          </h2>

          <p>
            Waiting for AI security analysis...
          </p>

        </div>

      </div>

    );

  }


  // ==========================================
  // SEVERITY COLOR
  // ==========================================

  const severityClass = (level) => {

    switch (level?.toUpperCase()) {

      case "CRITICAL":
        return "critical";

      case "HIGH":
        return "high";

      case "MEDIUM":
        return "medium";

      case "LOW":
        return "low";

      default:
        return "info";

    }

  };


  // ==========================================
  // COPY CODE
  // ==========================================

  const copyCode = async (text, type) => {

    if (!text) return;

    try {

      await navigator.clipboard.writeText(text);

      setCopied(type);

      setTimeout(() => {

        setCopied(null);

      }, 2000);

    }

    catch (error) {

      console.error(
        "Copy failed:",
        error
      );

    }

  };


  // ==========================================
  // TOGGLE RECOMMENDATION
  // ==========================================

  const toggleRecommendation = (index) => {

    setExpanded(

      expanded === index
        ? null
        : index

    );

  };


  const recommendations =
    Array.isArray(analysis.recommendations)
      ? analysis.recommendations
      : [];


  return (

    <div className="ai-card">

      {/* ==================================
          HEADER
      ================================== */}

      <div className="ai-card-header">

        <div className="ai-title-section">

          <div className="ai-icon">

            <ShieldAlert size={24} />

          </div>

          <div>

            <h2>
              AI Security Analyst
            </h2>

            <p>
              CloudGuardAI intelligent security recommendations
            </p>

          </div>

        </div>


        <div
          className={`ai-overall-severity ${severityClass(
            analysis.overall_severity
          )}`}
        >

          <span className="severity-dot"></span>

          {analysis.overall_severity || "INFO"}

        </div>

      </div>


      {/* ==================================
          SUMMARY
      ================================== */}

      <div className="ai-summary">

        <div className="ai-summary-item">

          <div className="summary-icon">

            <Target size={18} />

          </div>

          <div>

            <span>
              Findings
            </span>

            <strong>
              {recommendations.length}
            </strong>

          </div>

        </div>


        <div className="ai-summary-item">

          <div className="summary-icon">

            <AlertTriangle size={18} />

          </div>

          <div>

            <span>
              Overall Risk
            </span>

            <strong>
              {analysis.overall_severity || "N/A"}
            </strong>

          </div>

        </div>


        <div className="ai-summary-item">

          <div className="summary-icon">

            <Lightbulb size={18} />

          </div>

          <div>

            <span>
              AI Status
            </span>

            <strong>
              Analysis Ready
            </strong>

          </div>

        </div>

      </div>


      {/* ==================================
          RECOMMENDATIONS
      ================================== */}

      <div className="ai-recommendations">

        <div className="recommendations-title">

          <h3>
            Security Recommendations
          </h3>

          <span>
            {recommendations.length} findings
          </span>

        </div>


        {

          recommendations.length === 0 ? (

            <div className="no-recommendations">

              <Check size={22} />

              <div>

                <strong>
                  No security recommendations
                </strong>

                <p>
                  The latest AI analysis did not return any findings.
                </p>

              </div>

            </div>

          ) : (

            recommendations.map((item, index) => {

              const severity =
                item.severity || "INFO";

              const isOpen =
                expanded === index;

              return (

                <div
                  className={`ai-recommendation ${
                    isOpen ? "expanded" : ""
                  }`}
                  key={index}
                >

                  {/* FINDING HEADER */}

                  <button
                    type="button"
                    className="ai-rec-header"
                    onClick={() =>
                      toggleRecommendation(index)
                    }
                  >

                    <div className="rec-left">

                      <div
                        className={`rec-severity ${severityClass(
                          severity
                        )}`}
                      >

                        {severity.toUpperCase()}

                      </div>


                      <div className="rec-title">

                        <strong>

                          {
                            item.title ||
                            item.name ||
                            item.finding ||
                            "Security Finding"
                          }

                        </strong>

                        {

                          item.resource && (

                            <span>

                              {item.resource}

                            </span>

                          )

                        }

                      </div>

                    </div>


                    <div className="rec-toggle">

                      {

                        isOpen
                          ? <ChevronUp size={20} />
                          : <ChevronDown size={20} />

                      }

                    </div>

                  </button>


                  {/* EXPANDED CONTENT */}

                  {

                    isOpen && (

                      <div className="ai-rec-content">

                        {/* IMPACT */}

                        <div className="ai-detail">

                          <div className="detail-heading">

                            <AlertTriangle size={17} />

                            <span>
                              Business Impact
                            </span>

                          </div>

                          <p>

                            {
                              item.business_impact ||
                              item.impact ||
                              item.description ||
                              "This finding may increase the security risk of the connected cloud environment."
                            }

                          </p>

                        </div>


                        {/* RECOMMENDATION */}

                        <div className="ai-detail">

                          <div className="detail-heading">

                            <Lightbulb size={17} />

                            <span>
                              Recommended Action
                            </span>

                          </div>

                          <p>

                            {
                              item.recommendation ||
                              item.recommended_action ||
                              item.fix ||
                              "Review the affected resource and apply the security best practice recommended by CloudGuardAI."
                            }

                          </p>

                        </div>
                                                {/* AWS CLI FIX */}

                        {

                          item.aws_cli_fix && (

                            <div className="code-section">

                              <div className="code-header">

                                <div className="code-title">

                                  <Terminal size={17} />

                                  <span>
                                    AWS CLI Remediation
                                  </span>

                                </div>

                                <button
                                  type="button"
                                  className="copy-button"
                                  onClick={() =>
                                    copyCode(
                                      item.aws_cli_fix,
                                      `aws-${index}`
                                    )
                                  }
                                >

                                  {

                                    copied === `aws-${index}`

                                      ? (
                                        <>
                                          <Check size={15} />
                                          Copied
                                        </>
                                      )

                                      : (
                                        <>
                                          <Copy size={15} />
                                          Copy
                                        </>
                                      )

                                  }

                                </button>

                              </div>


                              <pre>

                                <code>
                                  {item.aws_cli_fix}
                                </code>

                              </pre>

                            </div>

                          )

                        }


                        {/* TERRAFORM FIX */}

                        {

                          item.terraform_fix && (

                            <div className="code-section">

                              <div className="code-header">

                                <div className="code-title">

                                  <Code2 size={17} />

                                  <span>
                                    Terraform Remediation
                                  </span>

                                </div>

                                <button
                                  type="button"
                                  className="copy-button"
                                  onClick={() =>
                                    copyCode(
                                      item.terraform_fix,
                                      `terraform-${index}`
                                    )
                                  }
                                >

                                  {

                                    copied === `terraform-${index}`

                                      ? (
                                        <>
                                          <Check size={15} />
                                          Copied
                                        </>
                                      )

                                      : (
                                        <>
                                          <Copy size={15} />
                                          Copy
                                        </>
                                      )

                                  }

                                </button>

                              </div>


                              <pre>

                                <code>
                                  {item.terraform_fix}
                                </code>

                              </pre>

                            </div>

                          )

                        }


                        {/* ESTIMATED FIX TIME */}

                        <div className="fix-time">

                          <Clock size={17} />

                          <span>
                            Estimated Fix Time
                          </span>

                          <strong>

                            {
                              item.estimated_fix_time ||
                              item.fix_time ||
                              "2–5 minutes"
                            }

                          </strong>

                        </div>

                      </div>

                    )

                  }

                </div>

              );

            })

          )

        }

      </div>

    </div>

  );

}

export default AISecurityAdvisor;