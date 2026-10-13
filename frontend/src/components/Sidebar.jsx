import { useState, useEffect } from "react";
import { Link, useLocation } from "react-router-dom";
import api from "../services/api";

import {
  LayoutDashboard,
  Cloud,
  ShieldCheck,
  FileText,
  Bot,
  Settings,
  LogOut,
  UserCircle,
  Activity,
  Search,
  Network,
  Users,
  Menu,
  X,
  Server,
  Database,
  HardDrive,
  Layers,
} from "lucide-react";

import "./Sidebar.css";


function Sidebar() {

  const location = useLocation();

  const [mobile, setMobile] = useState(
    window.innerWidth < 768
  );

  const [open, setOpen] = useState(false);
  const [awsStatus, setAwsStatus] = useState("loading");

  const [currentUser, setCurrentUser] = useState(() => {
    try {
      return JSON.parse(localStorage.getItem("user") || "{}");
    } catch {
      return {};
    }
  });

  const [verifiedRole, setVerifiedRole] = useState("");

  useEffect(() => {
    let isMounted = true;

    const loadOrgRole = async () => {
      const orgId = currentUser.organization || currentUser.organization_id;
      const userId = currentUser._id || currentUser.id;

      if (!orgId || !userId) return;

      try {
        const res = await api.get(`/organizations/${orgId}/members`);
        if (!isMounted) return;
        const memberList = res.data?.members || [];
        const currentMember = memberList.find(
          (m) => String(m.user_id) === String(userId)
        );
        if (currentMember?.role) {
          setVerifiedRole(currentMember.role);
        }
      } catch {
        // Safe fallback if org members call fails or user lacks org context
      }
    };

    loadOrgRole();

    return () => {
      isMounted = false;
    };
  }, [currentUser]);

  const formatRole = (roleStr) => {
    if (!roleStr) return "Member";
    const lower = String(roleStr).toLowerCase().trim();
    if (lower === "owner") return "Owner";
    if (lower === "admin" || lower === "administrator") return "Admin";
    if (lower === "viewer") return "Viewer";
    return lower.charAt(0).toUpperCase() + lower.slice(1);
  };

  const displayName =
    currentUser.name ||
    currentUser.displayName ||
    (currentUser.email ? currentUser.email.split("@")[0] : "User");

  const displayEmail = currentUser.email || "";
  const displayRole = formatRole(verifiedRole || currentUser.role);


  // ============================================================
  // RESPONSIVE SIDEBAR
  // ============================================================

  useEffect(() => {

    const resize = () => {

      setMobile(window.innerWidth < 768);

      if (window.innerWidth >= 768) {
        setOpen(false);
      }

    };

    window.addEventListener("resize", resize);

    return () => {
      window.removeEventListener("resize", resize);
    };

  }, []);

  useEffect(() => {
    let active = true;

    const loadAwsStatus = async () => {
      try {
        const response = await api.get("/aws/accounts");
        const accounts = Array.isArray(response.data?.accounts)
          ? response.data.accounts
          : [];

        if (active) {
          setAwsStatus(accounts.length > 0 ? "connected" : "disconnected");
        }
      } catch {
        if (active) {
          setAwsStatus("unavailable");
        }
      }
    };

    loadAwsStatus();

    const handleStatusUpdate = () => loadAwsStatus();
    window.addEventListener("aws-account-status-updated", handleStatusUpdate);

    return () => {
      active = false;
      window.removeEventListener("aws-account-status-updated", handleStatusUpdate);
    };
  }, [location.pathname]);

  useEffect(() => {
    const handleKeyDown = (event) => {
      if (event.key === "Escape") {
        setOpen(false);
      }
    };

    window.addEventListener("keydown", handleKeyDown);
    return () => window.removeEventListener("keydown", handleKeyDown);
  }, []);


  // ============================================================
  // SIDEBAR MENU
  // ============================================================

  const menu = [

    {
      name: "Dashboard",
      path: "/dashboard",
      icon: <LayoutDashboard size={20} />,
    },

    {
      name: "Findings",
      path: "/findings",
      icon: <Search size={20} />,
    },

    {
      name: "Cloud Scan",
      path: "/history",
      icon: <Cloud size={20} />,
    },

    {
      name: "EC2 Instances",
      path: "/ec2-instances",
      icon: <Server size={20} />,
    },

    {
      name: "S3 Buckets",
      path: "/s3-resources",
      icon: <Database size={20} />,
    },

    {
      name: "RDS Databases",
      path: "/rds-resources",
      icon: <HardDrive size={20} />,
    },

    {
      name: "VPC & Networks",
      path: "/network-resources",
      icon: <Layers size={20} />,
    },

    {
      name: "IAM Management",
      path: "/iam-management",
      icon: <Users size={20} />,
    },

    {
      name: "Security Center",
      path: "/security-center",
      icon: <ShieldCheck size={20} />,
    },

    // ==========================================================
    // SECURITY GRAPH
    // ==========================================================

    {
      name: "Security Graph",
      path: "/security-graph",
      icon: <Network size={20} />,
    },

    {
      name: "Reports",
      path: "/reports",
      icon: <FileText size={20} />,
    },

    {
      name: "AI Assistant",
      path: "/dashboard",
      icon: <Bot size={20} />,
    },

    // ==========================================================
    // SAAS TEAM MEMBERS
    // ==========================================================

    {
      name: "Team Members",
      path: "/team-members",
      icon: <Users size={20} />,
    },

    {
      name: "Settings",
      path: "/settings",
      icon: <Settings size={20} />,
    },

  ];


  // ============================================================
  // ACTIVE MENU
  // ============================================================

  const isActive = (path) => {

    if (path === "/dashboard") {
      return location.pathname === "/dashboard";
    }

    return (
      location.pathname === path ||
      location.pathname.startsWith(`${path}/`)
    );

  };


  // ============================================================
  // LOGOUT
  // ============================================================

  const handleLogout = () => {

    localStorage.removeItem("token");
    localStorage.removeItem("access_token");
    localStorage.removeItem("user");
    localStorage.removeItem("organization_id");

    window.location.href = "/";

  };


  // ============================================================
  // RENDER
  // ============================================================

  return (

    <>

      {/* ======================================================
          MOBILE MENU BUTTON
          ====================================================== */}

      {mobile && (

        <button
          type="button"
          className="menu-btn"
          onClick={() => setOpen(!open)}
          aria-label={open ? "Close navigation menu" : "Open navigation menu"}
          aria-expanded={open}
        >
          {open ? <X size={20} /> : <Menu size={20} />}
        </button>

      )}


      {mobile && open && (
        <button
          type="button"
          className="sidebar-backdrop"
          aria-label="Close navigation menu"
          onClick={() => setOpen(false)}
        />
      )}

      {/* ======================================================
          SIDEBAR
          ====================================================== */}

      <aside
        className={`sidebar ${
          mobile
            ? open
              ? "open"
              : "closed"
            : ""
        }`}
      >

        {/* ====================================================
            SIDEBAR TOP
            ==================================================== */}

        <div>

          {/* BRAND */}

          <div className="logo">

            <div className="logo-icon">
              <ShieldCheck size={34} />
            </div>

            <div>

              <h2>
                CloudGuardAI
              </h2>

              <p>
                Enterprise Security Platform
              </p>

            </div>

          </div>


          {/* ==================================================
              AWS CONNECTION STATUS
              ================================================== */}

          <div className={`connection-status is-${awsStatus}`} aria-live="polite">

            <Activity size={16} />

            <span>{
              awsStatus === "connected"
                ? "AWS Connected"
                : awsStatus === "disconnected"
                  ? "AWS Not Connected"
                  : awsStatus === "unavailable"
                    ? "AWS Status Unavailable"
                    : "Checking AWS Status"
            }</span>

            <span className="connection-dot"></span>

          </div>


          {/* ==================================================
              NAVIGATION
              ================================================== */}

          <nav className="sidebar-menu" aria-label="Main navigation">

            {menu.map((item) => (

              <Link
                key={item.name}
                to={item.path}

                className={
                  isActive(item.path)
                    ? "active"
                    : ""
                }
                aria-current={isActive(item.path) ? "page" : undefined}

                onClick={() => {

                  if (mobile) {
                    setOpen(false);
                  }

                }}
              >

                <span className="sidebar-icon">
                  {item.icon}
                </span>

                <span>
                  {item.name}
                </span>

              </Link>

            ))}

          </nav>

        </div>


        {/* ====================================================
            SIDEBAR FOOTER
            ==================================================== */}

        <div className="sidebar-footer">


          {/* USER */}

          <div className="user-card">

            <div className="avatar">
              <UserCircle size={32} />
            </div>

            <div className="user-info">

              <h4 title={displayName}>
                {displayName}
              </h4>

              <p title={displayEmail ? `${displayRole} • ${displayEmail}` : displayRole}>
                <span className="user-role-badge">{displayRole}</span>
                {displayEmail ? ` • ${displayEmail}` : ""}
              </p>

            </div>

          </div>


          {/* LOGOUT */}

          <button
            type="button"
            className="logout-btn"
            onClick={handleLogout}
          >

            <LogOut size={18} />

            <span>
              Logout
            </span>

          </button>


          {/* VERSION */}

          <div className="version">
            CloudGuardAI v2.0
          </div>

        </div>

      </aside>

    </>

  );

}


export default Sidebar;