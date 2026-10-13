import { useEffect, useState } from "react";
import "./RecentScans.css";

function RecentScans({ dashboard }) {
  const [scans, setScans] = useState([]);

  useEffect(() => {
    setScans(dashboard?.recent_scans || []);
  }, [dashboard]);

  const badgeColor = (level) => {
    switch ((level || "").toLowerCase()) {
      case "critical":
        return "#991b1b";

      case "high":
        return "#dc2626";

      case "medium":
        return "#f59e0b";

      case "low":
        return "#16a34a";

      default:
        return "#94a3a0";
    }
  };

  return (
    <div className="recent-card">
      <div className="recent-header">
        <div>
          <h2>Recent Cloud Scans</h2>
          <p>
            Latest AWS security scans performed by CloudGuardAI.
          </p>
        </div>
      </div>

      {scans.length === 0 ? (
        <div className="empty-box">
          <h3>No scans found</h3>
          <p>Run a cloud scan to view history.</p>
        </div>
      ) : (
        <div className="table-wrapper">
          <table className="recent-table">
            <thead>
              <tr>
                <th>AWS Account</th>
                <th>Risk Score</th>
                <th>Security Level</th>
                <th>Scan Time</th>
              </tr>
            </thead>

            <tbody>
              {scans.map((scan, index) => (
                <tr key={scan.scan_id || index}>
                  <td>{scan.account}</td>

                  <td>
                    <strong>{scan.risk_score}</strong>
                  </td>

                  <td>
                    <span
                      className="security-pill"
                      style={{
                        background: badgeColor(
                          scan.security_level
                        ),
                      }}
                    >
                      {scan.security_level}
                    </span>
                  </td>

                  <td>{scan.scan_time}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
}

export default RecentScans;