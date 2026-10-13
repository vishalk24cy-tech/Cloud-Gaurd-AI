import "./DashboardCards.css";

function DashboardCards({ dashboard, accounts = [], hasScanData = false }) {

  const cards = [
    {
      title: "Risk Score",
      value: hasScanData ? dashboard?.latest_risk_score ?? "—" : "—",
      icon: "◉",
      color: "#34d399",
      status: "Moderate Risk",
      update: hasScanData ? "From last completed scan" : "No scan data",
    },
    {
      title: "Average Risk",
      value: hasScanData ? dashboard?.average_risk_score ?? "—" : "—",
      icon: "↗",
      color: "#f97316",
      status: "Last 30 Days",
      update: hasScanData ? "Historical scan average" : "No scan data",
    },
    {
      title: "Security Level",
      value: hasScanData ? dashboard?.security_level ?? "Unknown" : "—",
      icon: "◆",
      color: "#16a34a",
      status: "Infrastructure Health",
      update: hasScanData ? "From last completed scan" : "No scan data",
    },
    {
      title: "AWS Accounts",
      value: Array.isArray(accounts) ? accounts.length : "—",
      icon: "☁",
      color: "#34d399",
      status: !Array.isArray(accounts)
        ? "Status unavailable"
        : accounts.length > 0
          ? "Connected"
          : "Not connected",
      update: "AWS accounts",
    },
    {
      title: "Resources",
      value: hasScanData ? dashboard?.total_resources ?? "—" : "—",
      icon: "▦",
      color: "#94a3a0",
      status: "Discovered",
      update: hasScanData ? "From last completed scan" : "No scan data",
    },
    {
      title: "Critical Findings",
      value: hasScanData ? dashboard?.critical_findings ?? "—" : "—",
      icon: "!",
      color: "#dc2626",
      status: "Requires Attention",
      update: hasScanData ? "From last completed scan" : "No scan data",
    },
    {
      title: "Compliance",
      value: !hasScanData || dashboard?.compliance_score == null
        ? "—"
        : `${dashboard.compliance_score}%`,
      icon: "✓",
      color: "#16a34a",
      status: "Compliance Score",
      update: hasScanData ? "From last completed scan" : "No scan data",
    },
    {
      title: "Total Scans",
      value: hasScanData ? dashboard?.total_scans ?? "—" : 0,
      icon: "⌕",
      color: "#ca8a04",
      status: hasScanData ? "Completed" : "None yet",
      update: "Scan history",
    },
  ];

  return (
    <div className="dashboard-cards">

      {cards.map((card) => (

        <div
          className="dashboard-card"
          key={card.title}
          style={{
            "--accent": card.color,
          }}
        >

          {/* TOP */}
          <div className="card-top">

            <div
              className="card-icon"
              style={{
                color: card.color,
                background: `${card.color}12`,
                borderColor: `${card.color}25`,
              }}
            >
              {card.icon}
            </div>

            <div
              className="card-status-dot"
              style={{
                background: card.color,
                boxShadow: `0 0 0 4px ${card.color}14`,
              }}
            />

          </div>


          {/* TITLE */}
          <div className="card-title">
            {card.title}
          </div>


          {/* VALUE */}
          <div
            className="card-value"
            style={{
              color: card.color,
            }}
          >
            {card.value}
          </div>


          {/* STATUS */}
          <div className="card-status">
            {card.status}
          </div>


          {/* UPDATE */}
          <div className="card-update">
            <span className="update-indicator"></span>
            {card.update}
          </div>

        </div>

      ))}

    </div>
  );
}

export default DashboardCards;