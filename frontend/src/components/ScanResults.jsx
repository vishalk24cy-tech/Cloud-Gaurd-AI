import { useEffect, useMemo, useState } from "react";
import "./ScanResults.css";

function ScanResults({ findings: dashboardFindings = [] }) {
  const [findings, setFindings] = useState([]);

  const [search, setSearch] = useState("");
  const [severity, setSeverity] = useState("ALL");

  const [expandedRow, setExpandedRow] = useState(null);

  // ============================================================
  // RECEIVE FINDINGS FROM DASHBOARD
  // ============================================================

  useEffect(() => {
    setFindings(dashboardFindings || []);
  }, [dashboardFindings]);


  // ============================================================
  // REFRESH
  // ============================================================

  const loadResults = () => {
    setFindings(dashboardFindings || []);
    setExpandedRow(null);
  };


  // ============================================================
  // BADGE COLOR
  // ============================================================

  const badgeColor = (level) => {
    switch ((level || "").toUpperCase()) {
      case "CRITICAL":
        return "#7f1d1d";

      case "HIGH":
        return "#dc2626";

      case "MEDIUM":
        return "#f59e0b";

      case "LOW":
        return "#16a34a";

      case "INFO":
        return "#94a3a0";

      default:
        return "#64748b";
    }
  };


  // ============================================================
  // SERVICE
  // ============================================================

  const getService = (finding) => {
    if (finding.bucket) return "Amazon S3";
    if (finding.user) return "AWS IAM";
    if (finding.instance) return "Amazon EC2";
    if (finding.database) return "Amazon RDS";
    if (finding.function) return "AWS Lambda";

    return finding.service || "AWS";
  };


  // ============================================================
  // RESOURCE
  // ============================================================

  const getResource = (finding) => {
    return (
      finding.bucket ||
      finding.user ||
      finding.instance ||
      finding.database ||
      finding.function ||
      finding.resource ||
      "-"
    );
  };


  // ============================================================
  // FINDING
  // ============================================================

  const getFinding = (finding) => {
    return finding.issue || "-";
  };


  // ============================================================
  // STATUS
  // ============================================================

  const getStatus = (finding) => {
    return finding.status || "Open";
  };


  // ============================================================
  // FILTER FINDINGS
  // ============================================================

  const filtered = useMemo(() => {

    return findings.filter((item) => {

      const q = search.trim().toLowerCase();

      const service =
        getService(item).toLowerCase();

      const resource =
        getResource(item).toLowerCase();

      const issue =
        getFinding(item).toLowerCase();

      const matchSearch =
        service.includes(q) ||
        resource.includes(q) ||
        issue.includes(q);

      const matchSeverity =
        severity === "ALL" ||
        (item.severity || "").toUpperCase() === severity;

      return matchSearch && matchSeverity;

    });

  }, [findings, search, severity]);


  // ============================================================
  // COPY FINDING
  // ============================================================

  const copyFinding = (finding, e) => {

    e.stopPropagation();

    navigator.clipboard.writeText(
      JSON.stringify(finding, null, 2)
    );

    alert("Finding copied successfully.");

  };


  // ============================================================
  // UI
  // ============================================================

  return (

    <div className="scan-card">

      {/* ======================================================
          HEADER
      ====================================================== */}

      <div className="scan-header">

        <div>

          <h2>
            Latest Scan Results
          </h2>

          <p>
            {filtered.length} Findings
          </p>

        </div>


        <button
          className="refresh-btn"
          onClick={loadResults}
        >
          Refresh
        </button>

      </div>


      {/* ======================================================
          SEARCH + FILTER
      ====================================================== */}

      <div className="scan-toolbar">

        <input
          type="text"
          placeholder="Search findings..."
          value={search}
          onChange={(e) =>
            setSearch(e.target.value)
          }
        />


        <select
          value={severity}
          onChange={(e) =>
            setSeverity(e.target.value)
          }
        >

          <option value="ALL">
            All Severity
          </option>

          <option value="CRITICAL">
            Critical
          </option>

          <option value="HIGH">
            High
          </option>

          <option value="MEDIUM">
            Medium
          </option>

          <option value="LOW">
            Low
          </option>

          <option value="INFO">
            Info
          </option>

        </select>

      </div>


      {/* ======================================================
          EMPTY STATE
      ====================================================== */}

      {filtered.length === 0 ? (

        <div className="empty-state">

          <h3>
            No Findings
          </h3>

          <p>
            No scan results found.
          </p>

        </div>

      ) : (


        /* ====================================================
           FINDINGS TABLE
        ==================================================== */

        <div className="table-wrapper">

          <table>

            <thead>

              <tr>

                <th>
                  Severity
                </th>

                <th>
                  Service
                </th>

                <th>
                  Resource
                </th>

                <th>
                  Finding
                </th>

                <th>
                  Status
                </th>

              </tr>

            </thead>


            <tbody>

              {filtered.map(
                (finding, index) => (

                  <tr
                    key={
                      finding.finding_id ||
                      finding.id ||
                      index
                    }
                  >

                    <td colSpan="5" style={{ padding: 0 }}>

                      <table
                        style={{
                          width: "100%",
                          borderCollapse: "collapse",
                        }}
                      >

                        <tbody>

                          {/* ==================================
                              MAIN FINDING ROW
                          ================================== */}

                          <tr
                            className="finding-row"

                            onClick={() =>
                              setExpandedRow(
                                expandedRow === index
                                  ? null
                                  : index
                              )
                            }
                          >

                            {/* SEVERITY */}

                            <td>

                              <span
                                className="severity-pill"

                                style={{
                                  background:
                                    badgeColor(
                                      finding.severity
                                    ),
                                }}
                              >

                                {finding.severity ||
                                  "UNKNOWN"}

                              </span>

                            </td>


                            {/* SERVICE */}

                            <td>

                              <span className="service-badge">

                                {getService(
                                  finding
                                )}

                              </span>

                            </td>


                            {/* RESOURCE */}

                            <td>

                              {getResource(
                                finding
                              )}

                            </td>


                            {/* FINDING */}

                            <td>

                              {getFinding(
                                finding
                              )}

                            </td>


                            {/* STATUS */}

                            <td>

                              <span
                                className={`status-badge ${getStatus(
                                  finding
                                ).toLowerCase()}`}
                              >

                                {getStatus(
                                  finding
                                )}

                              </span>

                            </td>

                          </tr>


                          {/* ==================================
                              EXPANDED DETAILS
                          ================================== */}

                          {expandedRow === index && (

                            <tr className="expanded-row">

                              <td colSpan="5">

                                <div className="expanded-content">


                                  <h4>
                                    Issue
                                  </h4>

                                  <p>
                                    {finding.issue ||
                                      "No issue information available."}
                                  </p>


                                  <h4>
                                    Severity
                                  </h4>

                                  <p>
                                    {finding.severity ||
                                      "-"}
                                  </p>


                                  <h4>
                                    Service
                                  </h4>

                                  <p>
                                    {getService(
                                      finding
                                    )}
                                  </p>


                                  <h4>
                                    Resource
                                  </h4>

                                  <p>
                                    {getResource(
                                      finding
                                    )}
                                  </p>


                                  <h4>
                                    Status
                                  </h4>

                                  <p>
                                    {getStatus(
                                      finding
                                    )}
                                  </p>


                                  <h4>
                                    Recommendation
                                  </h4>

                                  <p>
                                    {finding.recommendation ||
                                      "No recommendation available."}
                                  </p>


                                  <button
                                    className="copy-btn"

                                    onClick={(e) =>
                                      copyFinding(
                                        finding,
                                        e
                                      )
                                    }
                                  >
                                    Copy Finding JSON
                                  </button>

                                </div>

                              </td>

                            </tr>

                          )}

                        </tbody>

                      </table>

                    </td>

                  </tr>

                )
              )}

            </tbody>

          </table>

        </div>

      )}

    </div>
  );
}


export default ScanResults;