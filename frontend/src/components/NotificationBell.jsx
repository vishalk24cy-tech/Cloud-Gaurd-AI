import { useCallback, useEffect, useRef, useState } from "react";
import { Bell, BellRing, CheckCheck, RefreshCw, ShieldAlert, Trash2, X } from "lucide-react";
import api from "../services/api";
import "./NotificationBell.css";

function normalizeNotifications(data) {
  if (Array.isArray(data)) return data;
  if (Array.isArray(data?.notifications)) return data.notifications;
  if (Array.isArray(data?.data)) return data.data;
  if (Array.isArray(data?.results)) return data.results;
  return [];
}

function formatAge(value) {
  if (!value) return "";
  const ms = Date.now() - new Date(value).getTime();
  if (!Number.isFinite(ms) || ms < 0) return "";
  const minutes = Math.floor(ms / 60000);
  if (minutes < 1) return "just now";
  if (minutes < 60) return minutes + "m ago";
  const hours = Math.floor(minutes / 60);
  if (hours < 24) return hours + "h ago";
  const days = Math.floor(hours / 24);
  if (days < 30) return days + "d ago";
  return new Date(value).toLocaleDateString();
}

const SEVERITY_ORDER = ["CRITICAL", "HIGH", "MEDIUM", "LOW"];
const SEVERITY_FILTERS = ["ALL", ...SEVERITY_ORDER];

function NotificationBell({ className = "" }) {
  const [open, setOpen] = useState(false);
  const [notifications, setNotifications] = useState([]);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState(false);
  const [filter, setFilter] = useState("ALL");
  const [animating, setAnimating] = useState(false);
  const panelRef = useRef(null);
  const btnRef = useRef(null);
  const loadingRef = useRef(false);

  const loadNotifications = useCallback(async (silent = false) => {
    if (loadingRef.current) return;
    loadingRef.current = true;
    if (!silent) setLoading(true);
    setError(false);
    try {
      const response = await api.get("/notifications/", { params: { limit: 50 } });
      setNotifications(normalizeNotifications(response?.data));
    } catch {
      setError(true);
      setNotifications([]);
    } finally {
      loadingRef.current = false;
      if (!silent) setLoading(false);
    }
  }, []);

  useEffect(() => { void loadNotifications(); }, [loadNotifications]);

  const prevUnreadRef = useRef(0);
  const unreadCount = notifications.filter(
    (n) => String(n?.status || "").toLowerCase() !== "read"
  ).length;

  useEffect(() => {
    if (unreadCount > prevUnreadRef.current) {
      setAnimating(true);
      const t = setTimeout(() => setAnimating(false), 800);
      prevUnreadRef.current = unreadCount;
      return () => clearTimeout(t);
    }
    prevUnreadRef.current = unreadCount;
  }, [unreadCount]);

  useEffect(() => {
    if (!open) return;
    const handleClick = (event) => {
      if (
        panelRef.current && !panelRef.current.contains(event.target) &&
        btnRef.current && !btnRef.current.contains(event.target)
      ) { setOpen(false); }
    };
    const handleKey = (event) => { if (event.key === "Escape") setOpen(false); };
    document.addEventListener("mousedown", handleClick);
    document.addEventListener("keydown", handleKey);
    return () => {
      document.removeEventListener("mousedown", handleClick);
      document.removeEventListener("keydown", handleKey);
    };
  }, [open]);

  const markRead = async (id) => {
    if (!id) return;
    try {
      await api.put("/notifications/read/" + id);
      setNotifications((prev) =>
        prev.map((n) => (n._id || n.id) === id ? { ...n, status: "read" } : n)
      );
    } catch { /* non-critical */ }
  };

  const markAllRead = async () => {
    try {
      await api.put("/notifications/read-all");
      setNotifications((prev) => prev.map((n) => ({ ...n, status: "read" })));
    } catch { /* non-critical */ }
  };

  const deleteNotification = async (id, event) => {
    event.stopPropagation();
    if (!id) return;
    try {
      await api.delete("/notifications/" + id);
      setNotifications((prev) => prev.filter((n) => (n._id || n.id) !== id));
    } catch { /* non-critical */ }
  };

  const filtered =
    filter === "ALL"
      ? notifications
      : notifications.filter((n) => String(n?.severity || "").toUpperCase() === filter);

  const sortedNotifications = [...filtered].sort((a, b) => {
    const aRead = String(a?.status || "").toLowerCase() === "read";
    const bRead = String(b?.status || "").toLowerCase() === "read";
    if (aRead !== bRead) return aRead ? 1 : -1;
    const aSev = SEVERITY_ORDER.indexOf(String(a?.severity || "").toUpperCase());
    const bSev = SEVERITY_ORDER.indexOf(String(b?.severity || "").toUpperCase());
    if (aSev !== bSev) return (aSev === -1 ? 99 : aSev) - (bSev === -1 ? 99 : bSev);
    return new Date(b?.created_at || 0) - new Date(a?.created_at || 0);
  });

  const labelText = unreadCount > 0 ? "Security notifications — " + unreadCount + " unread" : "Security notifications";

  return (
    <div className={"nb-wrapper " + className}>
      <button
        ref={btnRef}
        type="button"
        className={"nb-btn" + (animating ? " nb-btn--ring" : "") + (open ? " nb-btn--open" : "")}
        onClick={() => setOpen((prev) => !prev)}
        aria-label={labelText}
        aria-expanded={open}
        aria-haspopup="dialog"
      >
        {animating ? <BellRing size={17} aria-hidden="true" /> : <Bell size={17} aria-hidden="true" />}
        {unreadCount > 0 && (
          <span className="nb-badge" aria-hidden="true">{unreadCount > 99 ? "99+" : unreadCount}</span>
        )}
      </button>
      {open && (
        <div ref={panelRef} className="nb-panel" role="dialog" aria-modal="true" aria-label="Security notifications">
          <div className="nb-panel-header">
            <div className="nb-panel-title">
              <ShieldAlert size={15} aria-hidden="true" />
              <h3>Security Alerts</h3>
              {unreadCount > 0 && <span className="nb-unread-pill">{unreadCount} unread</span>}
            </div>
            <div className="nb-panel-controls">
              {unreadCount > 0 && (
                <button type="button" className="nb-ctrl-btn" onClick={markAllRead} title="Mark all as read">
                  <CheckCheck size={13} />
                </button>
              )}
              <button type="button" className="nb-ctrl-btn" onClick={() => loadNotifications(false)} title="Refresh" disabled={loading}>
                <RefreshCw size={13} className={loading ? "nb-spin" : ""} />
              </button>
              <button type="button" className="nb-ctrl-btn nb-ctrl-btn--close" onClick={() => setOpen(false)} aria-label="Close">
                <X size={13} />
              </button>
            </div>
          </div>
          <div className="nb-filters" role="tablist">
            {SEVERITY_FILTERS.map((sev) => {
              const count = sev === "ALL" ? notifications.length
                : notifications.filter((n) => String(n?.severity || "").toUpperCase() === sev).length;
              return (
                <button key={sev} type="button" role="tab" aria-selected={filter === sev}
                  className={"nb-filter-tab nb-filter-tab--" + sev.toLowerCase() + (filter === sev ? " nb-filter-tab--active" : "")}
                  onClick={() => setFilter(sev)}>
                  {sev}{count > 0 && <span className="nb-filter-count">{count}</span>}
                </button>
              );
            })}
          </div>
          <div className="nb-list" role="list">
            {loading && sortedNotifications.length === 0 ? (
              <div className="nb-empty">
                <div className="nb-empty-icon nb-empty-icon--spin">⟳</div>
                <strong>Loading alerts…</strong>
                <p>Checking your cloud environment.</p>
              </div>
            ) : error ? (
              <div className="nb-empty">
                <div className="nb-empty-icon nb-empty-icon--error">!</div>
                <strong>Could not load alerts</strong>
                <p><button type="button" className="nb-retry-btn" onClick={() => loadNotifications(false)}>Retry</button></p>
              </div>
            ) : sortedNotifications.length === 0 ? (
              <div className="nb-empty">
                <div className="nb-empty-icon nb-empty-icon--ok">✓</div>
                <strong>{filter === "ALL" ? "Environment Secure" : "No " + filter + " alerts"}</strong>
                <p>{filter === "ALL" ? "No security alerts at the moment." : "No notifications at this severity level."}</p>
              </div>
            ) : (
              sortedNotifications.map((item, index) => {
                const id = item?._id || item?.id;
                const severity = String(item?.severity || "").toLowerCase();
                const isRead = String(item?.status || "").toLowerCase() === "read";
                const title = item?.title || "Security Alert";
                const message = item?.message || "Security event detected in your cloud environment.";
                const age = formatAge(item?.created_at);
                return (
                  <div
                    key={id || index}
                    className={"nb-item nb-item--" + (severity || "info") + (isRead ? " nb-item--read" : "")}
                    role="listitem"
                    onClick={() => !isRead && markRead(id)}
                    tabIndex={id ? 0 : undefined}
                    onKeyDown={(event) => {
                      if (event.key === "Enter" || event.key === " ") {
                        event.preventDefault();
                        if (!isRead) markRead(id);
                      }
                    }}
                  >
                    {!isRead && <span className="nb-item-dot" aria-hidden="true" />}
                    <div className="nb-item-body">
                      <div className="nb-item-top">
                        <strong className="nb-item-title">{title}</strong>
                        <div className="nb-item-meta">
                          {severity && <span className={"nb-sev nb-sev--" + severity}>{severity.toUpperCase()}</span>}
                          {id && (
                            <button type="button" className="nb-delete-btn" onClick={(e) => deleteNotification(id, e)} title="Dismiss">
                              <Trash2 size={11} />
                            </button>
                          )}
                        </div>
                      </div>
                      <p className="nb-item-msg">{message}</p>
                      {age && <small className="nb-item-age">{age}</small>}
                    </div>
                  </div>
                );
              })
            )}
          </div>
          {notifications.length > 0 && (
            <div className="nb-panel-footer">
              <span>{notifications.length} total alert{notifications.length !== 1 ? "s" : ""}</span>
            </div>
          )}
        </div>
      )}
    </div>
  );
}

export default NotificationBell;