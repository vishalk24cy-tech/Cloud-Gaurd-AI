import {
  LineChart,
  Line,
  XAxis,
  YAxis,
  Tooltip,
  ResponsiveContainer,
  CartesianGrid,
} from "recharts";

import "./RiskTrendChart.css";

function RiskTrendChart({ dashboard }) {
  const trend = dashboard?.risk_trend || [];

  const data = trend.map((item, index) => ({
    name: `Scan ${index + 1}`,
    risk: item.risk_score,
  }));

  return (
    <div className="trend-card">
      <div className="trend-header">
        <div>
          <h2>Risk Trend</h2>
          <p>Historical risk score across recent scans.</p>
        </div>
      </div>

      <ResponsiveContainer width="100%" height={340}>
        <LineChart data={data}>
          <CartesianGrid
            strokeDasharray="5 5"
            stroke="#e2e8f0"
          />

          <XAxis
            dataKey="name"
            tick={{ fill: "#64748b" }}
          />

          <YAxis
            domain={[0, 100]}
            tick={{ fill: "#64748b" }}
          />

          <Tooltip
            formatter={(value) => [`${value}`, "Risk Score"]}
          />

          <Line
            type="monotone"
            dataKey="risk"
            stroke="#34d399"
            strokeWidth={4}
            dot={{
              r: 5,
              fill: "#34d399",
            }}
            activeDot={{
              r: 8,
              fill: "#6ee7b7",
            }}
          />
        </LineChart>
      </ResponsiveContainer>

      <div className="trend-stats">
        <TrendBox
          title="Highest"
          value={dashboard?.highest_risk || 0}
          color="#ef4444"
        />

        <TrendBox
          title="Average"
          value={dashboard?.average_risk_score || 0}
          color="#34d399"
        />

        <TrendBox
          title="Lowest"
          value={dashboard?.lowest_risk || 0}
          color="#22c55e"
        />
      </div>
    </div>
  );
}

function TrendBox({ title, value, color }) {
  return (
    <div
      className="trend-box"
      style={{
        borderTop: `4px solid ${color}`,
      }}
    >
      <p>{title}</p>

      <h3
        style={{
          color,
        }}
      >
        {value}
      </h3>
    </div>
  );
}

export default RiskTrendChart;