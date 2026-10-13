import { useEffect, useState } from "react";
import api from "../services/api";

function ScanHistory() {
  const [scans, setScans] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");

  useEffect(() => {
    const loadScanHistory = async () => {
      try {
        setLoading(true);
        setError("");

        const response = await api.get("/cloud/history");

        setScans(response.data || []);
      } catch (err) {
        console.error("Failed to load scan history:", err);
        setError("Failed to load scan history.");
      } finally {
        setLoading(false);
      }
    };

    loadScanHistory();
  }, []);

  if (loading) {
    return <p>Loading scan history...</p>;
  }

  if (error) {
    return <p>{error}</p>;
  }

  return (
    <table
      style={{
        width: "100%",
        borderCollapse: "collapse",
      }}
    >
      <thead>
        <tr
          style={{
            background: "#1e293b",
            color: "white",
          }}
        >
          <th style={{ padding: "12px" }}>Date</th>
          <th>Status</th>
          <th>Security Score</th>
        </tr>
      </thead>

      <tbody>
        {scans.map((scan) => (
          <tr
            key={scan._id}
            style={{
              textAlign: "center",
              borderBottom: "1px solid #ddd",
            }}
          >
            <td style={{ padding: "12px" }}>
              {scan.scan_time
                ? new Date(scan.scan_time).toLocaleString()
                : "-"}
            </td>

            <td>{scan.status || "-"}</td>

            <td>
              {scan.risk_score !== undefined && scan.risk_score !== null
                ? `${Number(scan.risk_score).toFixed(2)}%`
                : "-"}
            </td>
          </tr>
        ))}
      </tbody>
    </table>
  );
}

export default ScanHistory;