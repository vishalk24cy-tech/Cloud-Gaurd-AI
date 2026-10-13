import {
  BarChart,
  Bar,
  XAxis,
  YAxis,
  Tooltip,
  ResponsiveContainer,
  CartesianGrid,
  Cell,
} from "recharts";

import "./ResourceChart.css";

function ResourceChart({ dashboard }) {
  const resources = dashboard?.resource_distribution || {};

  const data = [
    { name: "EC2", value: resources.ec2 || 0 },
    { name: "S3", value: resources.s3 || 0 },
    { name: "IAM", value: resources.iam || 0 },
    { name: "Lambda", value: resources.lambda || 0 },
    { name: "VPC", value: resources.vpc || 0 },
  ];

  const colors = [
    "#34d399",
    "#16a34a",
    "#ea580c",
    "#f59e0b",
    "#94a3a0",
  ];

  return (
    <div className="resource-card">

      <div className="resource-header">
        <div>
          <h2>AWS Resource Distribution</h2>
          <p>Overview of discovered AWS resources.</p>
        </div>
      </div>

      <ResponsiveContainer width="100%" height={320}>
        <BarChart data={data}>
          <CartesianGrid strokeDasharray="3 3" />

          <XAxis dataKey="name" />

          <YAxis />

          <Tooltip />

          <Bar
            dataKey="value"
            radius={[8, 8, 0, 0]}
          >
            {data.map((item, index) => (
              <Cell
                key={item.name}
                fill={colors[index]}
              />
            ))}
          </Bar>
        </BarChart>
      </ResponsiveContainer>

      <div className="resource-grid">

        {data.map((item, index) => (

          <div
            key={item.name}
            className="resource-box"
            style={{
              borderTop: `4px solid ${colors[index]}`,
            }}
          >
            <p>{item.name}</p>

            <h3
              style={{
                color: colors[index],
              }}
            >
              {item.value}
            </h3>

          </div>

        ))}

      </div>

    </div>
  );
}

export default ResourceChart;