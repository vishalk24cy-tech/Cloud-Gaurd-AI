import {
  PieChart,
  Pie,
  Cell,
  Tooltip,
  ResponsiveContainer,
  Legend,
} from "recharts";

import "./RiskChart.css";

function RiskChart({ dashboard }) {
  const severity = dashboard?.severity_distribution || {};

  const data = [
    { name: "High", value: severity.HIGH || 0 },
    { name: "Medium", value: severity.MEDIUM || 0 },
    { name: "Low", value: severity.LOW || 0 },
    { name: "Info", value: severity.INFO || 0 },
  ];

  const COLORS = [
    "#ef4444",
    "#f59e0b",
    "#22c55e",
    "#94a3a0",
  ];

  return (
    <div className="chart-card">
      <div className="chart-header">
        <div>
          <h2>Severity Distribution</h2>
          <p>Current findings grouped by severity.</p>
        </div>
      </div>

      <ResponsiveContainer width="100%" height={320}>
        <PieChart>
          <Pie
            data={data}
            dataKey="value"
            outerRadius={100}
            innerRadius={55}
            paddingAngle={3}
            label={({ name, percent }) =>
              percent > 0
                ? `${name} ${(percent * 100).toFixed(0)}%`
                : ""
            }
            labelLine={false}
          >
            {data.map((entry, index) => (
              <Cell
                key={entry.name}
                fill={COLORS[index]}
              />
            ))}
          </Pie>

          <Tooltip
            formatter={(value) => [value, "Findings"]}
          />

          <Legend
            verticalAlign="bottom"
            align="center"
            iconType="circle"
          />
        </PieChart>
      </ResponsiveContainer>

      <div className="severity-grid">
        <SeverityCard
          title="High"
          value={severity.HIGH || 0}
          color="#ef4444"
        />

        <SeverityCard
          title="Medium"
          value={severity.MEDIUM || 0}
          color="#f59e0b"
        />

        <SeverityCard
          title="Low"
          value={severity.LOW || 0}
          color="#22c55e"
        />

        <SeverityCard
          title="Info"
          value={severity.INFO || 0}
          color="#94a3a0"
        />
      </div>
    </div>
  );
}

function SeverityCard({ title, value, color }) {
  return (
    <div
      className="severity-card"
      style={{
        borderLeft: `5px solid ${color}`,
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

export default RiskChart;