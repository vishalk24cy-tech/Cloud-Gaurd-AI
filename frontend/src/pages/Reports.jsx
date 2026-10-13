import { useEffect, useState } from "react";
import { BarChart3, Bot, Download, FileText, ShieldCheck } from "lucide-react";
import api from "../services/api";
import "./Reports.css";

function Reports() {
  const [report, setReport] = useState(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    loadReport();
  }, []);

  const loadReport = async () => {
    try {
      const response = await api.get("/dashboard/");
      setReport(response.data);
    } catch (error) {
      console.error("Report loading failed:", error);
    } finally {
      setLoading(false);
    }
  };

  const downloadPDF = async () => {
    try {
      const response = await api.get("/report/pdf", {
        responseType: "blob",
      });

      const blob = new Blob([response.data], {
        type: "application/pdf",
      });

      const url = window.URL.createObjectURL(blob);

      const link = document.createElement("a");
      link.href = url;
      link.download = "CloudGuardAI_Security_Report.pdf";

      document.body.appendChild(link);
      link.click();

      link.remove();
      window.URL.revokeObjectURL(url);
    } catch (error) {
      console.error("PDF download failed:", error);
      alert("Failed to download PDF report.");
    }
  };

  if (loading) {
    return (
      <div className="reports-loading">
        <span className="loading-scan" aria-hidden="true" />
        <span>System initializing...</span>
      </div>
    );
  }

  return (
    <div className="reports-page">
      <div className="reports-header">
        <div>
          <span className="reports-kicker">SECURITY REPORTING</span>
          <h1><FileText size={22} aria-hidden="true" /> Security Reports</h1>

          <p>
            Enterprise cloud security assessment and compliance reports.
          </p>
        </div>

        <button
          className="download-btn"
          onClick={downloadPDF}
        >
          <Download size={16} /> Download PDF
        </button>
      </div>

      <div className="report-grid">
        <div className="report-card blue">
          <h3>Risk Score</h3>

          <h1>
            {report?.latest_risk_score ?? "—"}
          </h1>

          <p>
            Current security risk level
          </p>
        </div>

        <div className="report-card green">
          <h3>Security Level</h3>

          <h1>
            {report?.security_level || "Unknown"}
          </h1>

          <p>
            Infrastructure health
          </p>
        </div>

        <div className="report-card red">
          <h3>Critical Findings</h3>

          <h1>
            {report?.critical_findings ?? "—"}
          </h1>

          <p>
            Security issues detected
          </p>
        </div>
      </div>

      <div className="report-section">
        <h2>
          Latest Security Assessment
        </h2>

        <div className="assessment-card">
          <p>
            CloudGuardAI analysed your AWS environment and generated a
            complete security posture assessment.
          </p>

          <div className="report-details">
            <div>
              <span>
                AWS Resources
              </span>

              <strong>
                {report?.total_resources ?? "—"}
              </strong>
            </div>

            <div>
              <span>
                Total Scans
              </span>

              <strong>
                {report?.total_scans ?? "—"}
              </strong>
            </div>

            <div>
              <span>
                Compliance
              </span>

              <strong>
                {report?.compliance_score == null ? "—" : `${report.compliance_score}%`}
              </strong>
            </div>
          </div>
        </div>
      </div>

      <div className="report-section">
        <h2>
          Report Features
        </h2>

        <div className="feature-grid">
          <div>
            <ShieldCheck className="feature-icon" size={28} aria-hidden="true" />

            <h3>
              Security Analysis
            </h3>

            <p>
              AWS IAM, S3 and cloud resource assessment.
            </p>
          </div>

          <div>
            <Bot className="feature-icon" size={28} aria-hidden="true" />

            <h3>
              AI Recommendations
            </h3>

            <p>
              AI generated remediation suggestions.
            </p>
          </div>

          <div>
            <BarChart3 className="feature-icon" size={28} aria-hidden="true" />

            <h3>
              Compliance Report
            </h3>

            <p>
              Security posture and compliance tracking.
            </p>
          </div>
        </div>
      </div>
    </div>
  );
}

export default Reports;