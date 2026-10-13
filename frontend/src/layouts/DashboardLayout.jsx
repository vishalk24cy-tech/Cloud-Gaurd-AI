import { Outlet, useLocation, useNavigate } from "react-router-dom";
import { useEffect, useState, useCallback, useRef } from "react";
import { Bell, Moon, Search, ShieldCheck, Sun } from "lucide-react";

import Sidebar from "../components/Sidebar";
import api from "../services/api";

import "../styles/layout.css";
import "../styles/header.css";


function DashboardLayout({ theme, toggleTheme }) {

  const location = useLocation();
  const navigate = useNavigate();

  const [notifications, setNotifications] = useState([]);

  const [open, setOpen] = useState(false);
  const [search, setSearch] = useState("");

  const [notificationLoading, setNotificationLoading] =
    useState(false);

  // Prevent duplicate notification requests
  const notificationLoadingRef = useRef(false);


  // ============================================================
  // NORMALIZE NOTIFICATION RESPONSE
  // ============================================================

  const normalizeNotifications = (data) => {

    if (Array.isArray(data)) {
      return data;
    }


    if (Array.isArray(data?.notifications)) {
      return data.notifications;
    }


    if (Array.isArray(data?.data)) {
      return data.data;
    }


    if (Array.isArray(data?.results)) {
      return data.results;
    }


    return [];

  };


  // ============================================================
  // LOAD NOTIFICATIONS
  // ============================================================

  const loadNotifications = useCallback(
    async () => {

      // Prevent duplicate notification requests
      if (notificationLoadingRef.current) {

        console.log(
          "Notification request already running. Skipping duplicate request."
        );

        return;
      }


      notificationLoadingRef.current = true;


      try {

        setNotificationLoading(true);


        const response = await api.get(
          "/notifications/"
        );


        const normalized =
          normalizeNotifications(
            response?.data
          );


        setNotifications(
          normalized
        );

      }


      catch (error) {

        console.error(
          "Notification loading error:",
          error
        );


        // Notification failure must never
        // break the entire dashboard.

        setNotifications([]);

      }


      finally {

        // Allow future notification requests
        notificationLoadingRef.current = false;

        setNotificationLoading(false);

      }

    },
    []
  );


  // ============================================================
  // INITIAL LOAD
  // ============================================================
  //
  // No automatic 30-second refresh.
  // Notifications are loaded once when the layout mounts.
  // ============================================================

  useEffect(() => {

    loadNotifications();

  }, [loadNotifications]);


  // ============================================================
  // UNREAD NOTIFICATION COUNT
  // ============================================================

  const unreadCount =
    notifications.filter(
      (item) => {

        const status =
          String(
            item?.status || ""
          ).toLowerCase();


        return status !== "read";

      }
    ).length;


  // ============================================================
  // MARK NOTIFICATION AS READ
  // ============================================================

  const markRead = async (id) => {

    if (!id) {
      return;
    }


    try {

      await api.put(
        `/notifications/read/${id}`
      );


      // Reload notifications after marking as read
      await loadNotifications();

    }


    catch (error) {

      console.error(
        "Read notification error:",
        error
      );

    }

  };


  // ============================================================
  // THEME
  // ============================================================

  const isDark =
    theme === "dark";

  const currentPage = {
    "/onboarding": "Getting started",
    "/dashboard": "Security overview",
    "/findings": "Security findings",
    "/remediation": "Remediation",
    "/security-graph": "Security graph",
    "/history": "Cloud scan history",
    "/reports": "Security reports",
    "/security-center": "Security center",
    "/compliance": "Compliance",
    "/connect-aws": "Connect AWS",
    "/usage": "Usage and plan",
    "/settings": "Settings",
    "/team-members": "Team members",
  }[location.pathname] || "Cloud security";

  const submitSearch = (event) => {
    event.preventDefault();
    const query = search.trim();
    if (!query) return;
    navigate(`/findings?search=${encodeURIComponent(query)}`);
  };


  // ============================================================
  // RENDER
  // ============================================================

  return (

    <div
      className={`app-layout ${
        isDark
          ? "dark-theme"
          : "light-theme"
      }`}
    >


      {/* ========================================================
          SIDEBAR
      ======================================================== */}

      <Sidebar />


      <div className="main-section">


        {/* ======================================================
            TOP HEADER
        ====================================================== */}

        <header className="top-header">


          {/* ====================================================
              BRAND
          ==================================================== */}

          <div className="header-brand">


            <div className="header-brand-icon">
              <ShieldCheck size={20} aria-hidden="true" />
            </div>


            <div>

              <h1>
                CloudGuardAI
              </h1>


              <p>
                {currentPage}
              </p>

            </div>


          </div>


          <form className="header-search" role="search" onSubmit={submitSearch}>
            <Search size={17} aria-hidden="true" />
            <input
              aria-label="Search resources, findings, or recommendations"
              placeholder="Search resources, findings, or recommendations..."
              value={search}
              onChange={(event) => setSearch(event.target.value)}
            />
            <button type="submit" aria-label="Search">
              <Search size={15} aria-hidden="true" />
            </button>
          </form>


          {/* ====================================================
              HEADER ACTIONS
          ==================================================== */}

          <div className="header-right">


            {/* ==================================================
                THEME TOGGLE
            ================================================== */}

            <button
              type="button"
              className="theme-toggle"
              onClick={toggleTheme}
              aria-label={
                isDark
                  ? "Switch to light mode"
                  : "Switch to dark mode"
              }
            >

              <span className="theme-icon">

                {
                  isDark
                    ? <Sun size={17} aria-hidden="true" />
                    : <Moon size={16} aria-hidden="true" />
                }

              </span>


              <span>

                {
                  isDark
                    ? "Light"
                    : "Dark"
                }

              </span>

            </button>


            {/* ==================================================
                NOTIFICATIONS
            ================================================== */}

            <div className="notification-wrapper">


              <button
                type="button"
                className="notification-btn"
                onClick={() =>
                  setOpen(!open)
                }
                aria-label="Security notifications"
                aria-expanded={open}
              >

                <span className="notification-icon">
                  <Bell size={17} aria-hidden="true" />
                </span>


                {
                  unreadCount > 0 && (

                    <span className="notification-count">

                      {
                        unreadCount > 99
                          ? "99+"
                          : unreadCount
                      }

                    </span>

                  )
                }


              </button>


              {/* ==================================================
                  NOTIFICATION PANEL
              ================================================== */}

              {
                open && (

                  <div className="notification-panel">


                    {/* ============================================
                        HEADER
                    ============================================ */}

                    <div className="notification-header">


                      <div>

                        <h3>
                          Security Alerts
                        </h3>


                        <span>

                          {
                            notificationLoading

                              ? "Updating alerts..."

                              : unreadCount > 0

                                ? `${unreadCount} unread alert${
                                    unreadCount > 1
                                      ? "s"
                                      : ""
                                  }`

                                : "No unread alerts"
                          }

                        </span>

                      </div>


                      <button
                        type="button"
                        className="notification-close"
                        onClick={() =>
                          setOpen(false)
                        }
                        aria-label="Close notifications"
                      >
                        ×
                      </button>


                    </div>


                    {/* ============================================
                        NOTIFICATION LIST
                    ============================================ */}

                    <div className="notification-list">


                      {
                        notificationLoading &&
                        notifications.length === 0

                          ? (

                            <div className="no-alert">

                              <div className="no-alert-icon">
                                ◌
                              </div>


                              <strong>
                                Loading Alerts
                              </strong>


                              <p>
                                Checking your cloud
                                environment...
                              </p>

                            </div>

                          )

                          : notifications.length === 0

                            ? (

                              <div className="no-alert">

                                <div className="no-alert-icon">
                                  ✓
                                </div>


                                <strong>
                                  Environment Secure
                                </strong>


                                <p>
                                  No security alerts
                                  at the moment.
                                </p>

                              </div>

                            )

                            : (

                              notifications
                                .slice(0, 5)
                                .map(
                                  (
                                    item,
                                    index
                                  ) => {

                                    const severity =
                                      item?.severity
                                        ? String(
                                            item.severity
                                          ).toLowerCase()
                                        : "";


                                    const notificationId =
                                      item?._id ||
                                      item?.id;


                                    const status =
                                      String(
                                        item?.status ||
                                        ""
                                      ).toLowerCase();


                                    const isRead =
                                      status ===
                                      "read";


                                    return (

                                      <div
                                        key={
                                          notificationId ||
                                          index
                                        }
                                        className={`notification-item ${
                                          severity
                                            ? `severity-${severity}`
                                            : ""
                                        } ${
                                          isRead
                                            ? "read"
                                            : "unread"
                                        }`}
                                        onClick={() =>
                                          markRead(
                                            notificationId
                                          )
                                        }
                                        role={
                                          notificationId
                                            ? "button"
                                            : undefined
                                        }
                                        tabIndex={
                                          notificationId
                                            ? 0
                                            : undefined
                                        }
                                        onKeyDown={(
                                          event
                                        ) => {

                                          if (
                                            event.key ===
                                              "Enter" ||
                                            event.key ===
                                              " "
                                          ) {

                                            event.preventDefault();


                                            markRead(
                                              notificationId
                                            );

                                          }

                                        }}
                                      >


                                        {/* =================================
                                            NOTIFICATION TOP
                                        ================================== */}

                                        <div className="notification-item-top">


                                          <strong>

                                            {
                                              item?.title ||
                                              "Security Alert"
                                            }

                                          </strong>


                                          {
                                            item?.severity && (

                                              <span className="notification-severity">

                                                {
                                                  String(
                                                    item.severity
                                                  ).toUpperCase()
                                                }

                                              </span>

                                            )
                                          }


                                        </div>


                                        {/* =================================
                                            MESSAGE
                                        ================================== */}

                                        <p>

                                          {
                                            item?.message ||
                                            "Security event detected in your cloud environment."
                                          }

                                        </p>


                                        {/* =================================
                                            TIME
                                        ================================== */}

                                        {
                                          item?.created_at && (

                                            <small>

                                              {
                                                new Date(
                                                  item.created_at
                                                ).toLocaleString()
                                              }

                                            </small>

                                          )
                                        }


                                      </div>

                                    );

                                  }
                                )

                            )
                      }


                    </div>


                  </div>

                )
              }


            </div>


            {/* ==================================================
                SYSTEM STATUS
            ================================================== */}

            <div
              className="status-badge"
              title="CloudGuardAI services are operational"
            >

              <span className="status-dot"></span>


              <span>
                System Online
              </span>

            </div>


            {/* ==================================================
                USER PROFILE
            ================================================== */}

            <button
              type="button"
              className="profile"
              title="Administrator"
              aria-label="Open administrator profile"
            >
              A
            </button>


          </div>


        </header>


        {/* ======================================================
            PAGE CONTENT
        ====================================================== */}

        <main className="page-content">

          <Outlet />

        </main>


      </div>


    </div>

  );

}


export default DashboardLayout;