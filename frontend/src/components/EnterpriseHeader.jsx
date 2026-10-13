import { useState, useRef, useEffect } from "react";
import { useNavigate } from "react-router-dom";

import "./EnterpriseHeader.css";
import api from "../services/api";
import NotificationBell from "./NotificationBell";

function EnterpriseHeader({ onRefresh, awsConnected, lastScan }) {
  const navigate = useNavigate();

  const [showScanner, setShowScanner] = useState(false);
  const [scanStatus, setScanStatus] = useState("queued");
  const [scanError, setScanError] = useState("");
  const [startingScan, setStartingScan] = useState(false);

  const pollingRef = useRef(null);

  // ==========================================================
  // STOP POLLING
  // ==========================================================

  const stopPolling = () => {
    if (pollingRef.current) {
      clearInterval(pollingRef.current);
      pollingRef.current = null;
    }
  };

  // ==========================================================
  // CHECK SCAN JOB
  // ==========================================================

  const checkScanJob = async (jobId) => {
    try {
      const response = await api.get(`/scan-jobs/${jobId}`);

      const job = response.data?.job;

      if (!job) {
        console.warn("[SCAN JOB] No job returned");
        return;
      }

      const status = job.status || "queued";

      console.log("[SCAN JOB STATUS]", status);

      setScanStatus(status);

      // ------------------------------------------------------
      // COMPLETED
      // ------------------------------------------------------

      if (status === "completed") {
        stopPolling();

        setScanStatus("completed");
        setStartingScan(false);

        if (onRefresh) {
          onRefresh();
        }

        return;
      }

      // ------------------------------------------------------
      // FAILED
      // ------------------------------------------------------

      if (status === "failed") {
        stopPolling();

        setScanStatus("failed");
        setStartingScan(false);

        const message =
          job.error_message ||
          "AWS Security Scan Failed.";

        setScanError(message);

        console.error("[SCAN FAILED]", message);

        return;
      }

      // ------------------------------------------------------
      // OTHER STATES
      // queued / running / retrying
      // ------------------------------------------------------

      setScanStatus(status);
    } catch (err) {
      console.error(
        "[SCAN JOB POLLING ERROR]",
        err
      );
    }
  };

  // ==========================================================
  // START POLLING
  // ==========================================================

  const pollScanJob = (jobId) => {
    stopPolling();

    // Check immediately
    checkScanJob(jobId);

    // Continue every 2 seconds
    pollingRef.current = setInterval(() => {
      checkScanJob(jobId);
    }, 2000);
  };

  // ==========================================================
  // START AWS SCAN
  // ==========================================================

  const startScan = async () => {
    console.log("[START SCAN] Button clicked");

    try {
      // Prevent duplicate scans
      if (startingScan) {
        console.log(
          "[START SCAN] Scan already starting..."
        );
        return;
      }

      setStartingScan(true);
      setScanError("");
      setScanStatus("queued");

      // Open scanner immediately
      setShowScanner(true);

      // ------------------------------------------------------
      // GET AWS ACCOUNTS
      // ------------------------------------------------------

      console.log(
        "[START SCAN] Getting AWS accounts..."
      );

      const accountResponse =
        await api.get("/aws/accounts");

      console.log(
        "[START SCAN] AWS accounts response:",
        accountResponse.data
      );

      const accounts =
        accountResponse.data?.accounts;

      if (
        !accounts ||
        accounts.length === 0
      ) {
        setShowScanner(false);
        setStartingScan(false);

        alert(
          "No AWS Account Connected. Please connect an AWS account first."
        );

        return;
      }

      const accountId =
        accounts[0]?._id;

      if (!accountId) {
        throw new Error(
          "Connected AWS account ID was not found."
        );
      }

      console.log(
        "[START SCAN] Account ID:",
        accountId
      );

      // ------------------------------------------------------
      // CREATE SCAN JOB
      // ------------------------------------------------------

      console.log(
        "[START SCAN] Creating scan job..."
      );

      const response =
        await api.post(
          `/scan-jobs?account_id=${encodeURIComponent(
            accountId
          )}`
        );

      console.log(
        "[START SCAN] Scan job response:",
        response.data
      );

      const job =
        response.data?.job;

      const jobId =
        job?._id;

      if (!jobId) {
        throw new Error(
          "Scan job ID was not returned by the server."
        );
      }

      console.log(
        "[START SCAN] Job ID:",
        jobId
      );

      const initialStatus =
        job.status || "queued";

      setScanStatus(initialStatus);

      // ------------------------------------------------------
      // START POLLING
      // ------------------------------------------------------

      pollScanJob(jobId);
    } catch (err) {
      console.error(
        "[AWS SCAN ERROR]",
        err
      );

      stopPolling();

      setStartingScan(false);

      setShowScanner(false);

      const message =
        err.response?.data?.detail ||
        err.response?.data?.message ||
        err.message ||
        "Failed to Start AWS Scan.";

      alert(message);
    }
  };

  // ==========================================================
  // DOWNLOAD SECURITY REPORT
  // ==========================================================

  const downloadReport = async () => {
    try {
      alert(
        "Generating Security Report..."
      );

      const response =
        await api.get(
          "/report/pdf",
          {
            responseType: "blob",
          }
        );

      const blob = new Blob(
        [response.data],
        {
          type: "application/pdf",
        }
      );

      const url =
        window.URL.createObjectURL(blob);

      const link =
        document.createElement("a");

      link.href = url;

      link.download =
        "CloudGuardAI_Security_Report.pdf";

      document.body.appendChild(link);

      link.click();

      link.remove();

      window.URL.revokeObjectURL(url);

      alert(
        "Security Report Generated Successfully"
      );
    } catch (err) {
      console.error(
        "[REPORT DOWNLOAD ERROR]",
        err
      );

      let message =
        "Failed to Generate Security Report.";

      if (
        err.response?.data instanceof Blob
      ) {
        try {
          const text =
            await err.response.data.text();

          const data =
            JSON.parse(text);

          message =
            data.detail ||
            message;
        } catch {
          // Keep default message
        }
      } else if (
        err.response?.data?.detail
      ) {
        message =
          err.response.data.detail;
      }

      alert(message);
    }
  };

  // ==========================================================
  // CLOSE SCANNER
  // ==========================================================

  const closeScanner = () => {
    stopPolling();

    setShowScanner(false);
    setStartingScan(false);
    setScanError("");
  };

  // ==========================================================
  // VIEW RESULTS
  // ==========================================================

  const viewResults = () => {
    stopPolling();

    setShowScanner(false);
    setStartingScan(false);

    if (onRefresh) {
      onRefresh();
    }

    navigate("/findings");
  };

  // ==========================================================
  // CLEANUP
  // ==========================================================

  useEffect(() => {
    return () => {
      stopPolling();
    };
  }, []);

  // ==========================================================
  // UI
  // ==========================================================

  return (
    <>
      <div className="enterprise-header">
        <div className="header-top">

          {/* HEADER TITLE */}
          <div className="header-title">
            <h1>
              CloudGuardAI Security Operations
            </h1>

            <p>
              Monitor, detect, and secure your
              cloud infrastructure with
              AI-powered insights.
            </p>

            <div className="scan-info">
              Last scan: {lastScan}
            </div>
          </div>

          {/* HEADER ACTIONS */}
          <div className="header-actions">

            <button
              type="button"
              className="header-btn primary-btn"
              onClick={startScan}
              disabled={startingScan}
            >
              {startingScan
                ? "Scan Starting..."
                : "Start New Scan"}
            </button>

            <button
              type="button"
              className="header-btn secondary-btn"
              onClick={downloadReport}
            >
              Generate Report
            </button>

            <NotificationBell />

          </div>
        </div>
      </div>

      {/* ======================================================
          SCAN MODAL
      ====================================================== */}

      {showScanner && (
        <div className="scan-overlay">

          <div className="scan-modal">

            <h2>
              CloudGuardAI Enterprise Scanner
            </h2>

            <p>
              {scanStatus === "queued"
                ? "Scan job queued. Waiting for worker..."
                : scanStatus === "running"
                ? "AWS security scan is running..."
                : scanStatus === "retrying"
                ? "Scan is being retried..."
                : scanStatus === "completed"
                ? "AWS security scan completed."
                : scanStatus === "failed"
                ? "AWS security scan failed."
                : "Preparing security scan..."}
            </p>

            {/* PROGRESS BAR */}

            <div className="progress-bar">

              <div
                className="progress-fill"
                style={{
                  width:
                    scanStatus === "completed"
                      ? "100%"
                      : scanStatus === "running"
                      ? "60%"
                      : scanStatus === "retrying"
                      ? "45%"
                      : scanStatus === "failed"
                      ? "100%"
                      : "10%",
                }}
              />

            </div>

            {/* PROGRESS TEXT */}

            <div className="progress-text">

              {scanStatus === "completed"
                ? "100%"
                : scanStatus === "running"
                ? "60%"
                : scanStatus === "retrying"
                ? "45%"
                : scanStatus === "failed"
                ? "100%"
                : "10%"}

            </div>

            {/* STATUS */}

            <div className="scan-status">
              Status:{" "}
              <strong>
                {scanStatus.toUpperCase()}
              </strong>
            </div>

            {/* ERROR */}

            {scanStatus === "failed" &&
              scanError && (
                <div
                  style={{
                    marginTop: "15px",
                    padding: "12px",
                    borderRadius: "8px",
                    background:
                      "rgba(239, 68, 68, 0.12)",
                    color: "#fca5a5",
                    fontSize: "14px",
                  }}
                >
                  {scanError}
                </div>
              )}

            {/* SUCCESS */}

            {scanStatus === "completed" && (
              <div className="scan-success">

                <h3>
                  Scan Completed Successfully
                </h3>

                <p>
                  Security findings have been
                  updated.
                </p>

                <button
                  type="button"
                  onClick={viewResults}
                  className="close-btn"
                >
                  View Results
                </button>

              </div>
            )}

            {/* FAILED */}

            {scanStatus === "failed" && (
              <div className="scan-success">

                <h3>
                  Scan Failed
                </h3>

                <button
                  type="button"
                  onClick={closeScanner}
                  className="close-btn"
                >
                  Close
                </button>

              </div>
            )}

          </div>
        </div>
      )}
    </>
  );
}

export default EnterpriseHeader;