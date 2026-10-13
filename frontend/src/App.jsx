import { lazy, Suspense, useState } from "react";
import {
  BrowserRouter,
  Routes,
  Route,
  Navigate,
} from "react-router-dom";

const Login = lazy(() => import("./pages/Login"));
const Register = lazy(() => import("./pages/Register"));
const Dashboard = lazy(() => import("./pages/Dashboard"));
const History = lazy(() => import("./pages/History"));
const Reports = lazy(() => import("./pages/Reports"));
const SecurityCenter = lazy(() => import("./pages/SecurityCenter"));
const SecurityGraph = lazy(() => import("./pages/SecurityGraph"));
const ConnectAWS = lazy(() => import("./pages/ConnectAWS"));
const Findings = lazy(() => import("./pages/Findings"));
const Remediation = lazy(() => import("./pages/Remediation"));
const Compliance = lazy(() => import("./pages/Compliance"));
const Usage = lazy(() => import("./pages/Usage"));
const Settings = lazy(() => import("./pages/Settings"));
const TeamMembers = lazy(() => import("./pages/TeamMembers"));
const Onboarding = lazy(() => import("./pages/Onboarding"));
const EC2Instances = lazy(() => import("./pages/EC2Instances"));
const S3Resources = lazy(() => import("./pages/S3Resources"));
const RDSResources = lazy(() => import("./pages/RDSResources"));
const NetworkResources = lazy(() => import("./pages/NetworkResources"));
const IAMManagement = lazy(() => import("./pages/IAMManagement"));

import DashboardLayout from "./layouts/DashboardLayout";


/* =========================================================
   PRIVATE ROUTE
   ========================================================= */

function PrivateRoute({ children }) {

  const token =
    localStorage.getItem("token");

  if (!token) {

    return (
      <Navigate
        to="/"
        replace
      />
    );

  }

  return children;
}


/* =========================================================
   APPLICATION
   ========================================================= */

function App() {

  const [theme, setTheme] = useState("dark");

  const toggleTheme = () => {
    setTheme((current) =>
      current === "dark" ? "light" : "dark"
    );
  };

  return (

    <BrowserRouter>

      <Suspense
        fallback={(
          <div className="route-loading" role="status" aria-live="polite">
            Loading workspace...
          </div>
        )}
      >
      <Routes>


        {/* =====================================================
            PUBLIC ROUTES
        ====================================================== */}

        <Route
          path="/"
          element={<Login />}
        />

        <Route
          path="/register"
          element={<Register />}
        />


        {/* =====================================================
            PROTECTED APPLICATION
        ====================================================== */}

        <Route
          element={
            <PrivateRoute>
              <DashboardLayout
                theme={theme}
                toggleTheme={toggleTheme}
              />
            </PrivateRoute>
          }
        >


          {/* =================================================
              SAAS ONBOARDING
          ================================================== */}

          <Route
            path="/onboarding"
            element={<Onboarding />}
          />


          {/* =================================================
              DASHBOARD
          ================================================== */}

          <Route
            path="/dashboard"
            element={<Dashboard />}
          />


          {/* =================================================
              SECURITY FINDINGS
          ================================================== */}

          <Route
            path="/findings"
            element={<Findings />}
          />


          {/* =================================================
              REMEDIATION CENTER
          ================================================== */}

          <Route
            path="/remediation"
            element={<Remediation />}
          />


          {/* =================================================
              SECURITY GRAPH
          ================================================== */}

          <Route
            path="/security-graph"
            element={<SecurityGraph />}
          />


          {/* =================================================
              SCAN HISTORY
          ================================================== */}

          <Route
            path="/history"
            element={<History />}
          />


          {/* =================================================
              EC2 INSTANCES INVENTORY
          ================================================== */}

          <Route
            path="/ec2-instances"
            element={<EC2Instances />}
          />


          {/* =================================================
              S3 RESOURCE MANAGEMENT
          ================================================== */}

          <Route
            path="/s3-resources"
            element={<S3Resources />}
          />


          {/* =================================================
              RDS DATABASE MANAGEMENT
          ================================================== */}

          <Route
            path="/rds-resources"
            element={<RDSResources />}
          />


          {/* =================================================
              VPC & NETWORK RESOURCE MANAGEMENT
          ================================================== */}

          <Route
            path="/network-resources"
            element={<NetworkResources />}
          />


          {/* =================================================
              IAM RESOURCE MANAGEMENT
          ================================================== */}

          <Route
            path="/iam-management"
            element={<IAMManagement />}
          />


          {/* =================================================
              SECURITY REPORTS
          ================================================== */}

          <Route
            path="/reports"
            element={<Reports />}
          />


          {/* =================================================
              SECURITY CENTER
          ================================================== */}

          <Route
            path="/security-center"
            element={<SecurityCenter />}
          />


          {/* =================================================
              COMPLIANCE CENTER
          ================================================== */}

          <Route
            path="/compliance"
            element={<Compliance />}
          />


          {/* =================================================
              AWS CONNECTION
          ================================================== */}

          <Route
            path="/connect-aws"
            element={<ConnectAWS />}
          />


          {/* =================================================
              SAAS USAGE & QUOTA
          ================================================== */}

          <Route
            path="/usage"
            element={<Usage />}
          />


          {/* =================================================
              SAAS ORGANIZATION SETTINGS
          ================================================== */}

          <Route
            path="/settings"
            element={<Settings />}
          />


          {/* =================================================
              SAAS TEAM MEMBERS
          ================================================== */}

          <Route
            path="/team-members"
            element={<TeamMembers />}
          />

        </Route>


        {/* =====================================================
            FALLBACK ROUTE
        ====================================================== */}

        <Route
          path="*"
          element={
            <Navigate
              to="/"
              replace
            />
          }
        />

      </Routes>
      </Suspense>

    </BrowserRouter>

  );
}


export default App;