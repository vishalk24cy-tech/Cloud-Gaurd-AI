import { useState } from "react";
import { useNavigate } from "react-router-dom";

import api from "../services/api";
import "./AWSAccountCard.css";

function AWSAccountCard({
  accounts = [],
  onRefresh,
}) {

  const navigate = useNavigate();

  const [scanningId, setScanningId] = useState(null);
  const [deletingId, setDeletingId] = useState(null);
  const [verifyingId, setVerifyingId] = useState(null);
  const [error, setError] = useState("");

  // ==========================================
  // VERIFY AWS CONNECTION
  // ==========================================

  const verifyConnection = async (accountId) => {
    try {
      setError("");
      setVerifyingId(accountId);
      await api.post(`/aws/account/${accountId}/test-connection`);
      alert("✅ AWS Connection Verified Successfully");
      if (onRefresh) {
        await onRefresh();
      }
    } catch (err) {
      console.error("AWS Verification Error:", err);
      const message =
        err.response?.data?.detail ||
        err.response?.data?.message ||
        "AWS connection verification failed.";
      setError(message);
      alert("❌ " + message);
      if (onRefresh) {
        await onRefresh();
      }
    } finally {
      setVerifyingId(null);
    }
  };


  // ==========================================
  // RUN AWS SCAN
  // ==========================================

  const runScan = async (accountId) => {

    try {

      setError("");

      setScanningId(accountId);

      const response = await api.get(
        `/cloud/aws/scan/${accountId}`
      );


      if (response.data.status === "success") {

        alert(
          "✅ AWS Security Scan Completed Successfully"
        );

      } else {

        alert(
          "AWS Security Scan Completed"
        );

      }


      // Refresh Dashboard data
      if (onRefresh) {

        await onRefresh();

      }

    }

    catch (err) {

      console.error(
        "AWS Scan Error:",
        err
      );

      const message =
        err.response?.data?.detail ||
        err.response?.data?.message ||
        "AWS Security Scan Failed.";

      setError(message);

      alert(message);

    }

    finally {

      setScanningId(null);

    }

  };


  // ==========================================
  // DELETE AWS ACCOUNT
  // ==========================================

  const removeAccount = async (accountId) => {

    const confirmed = window.confirm(
      "Are you sure you want to disconnect this AWS account?"
    );


    if (!confirmed) {

      return;

    }


    try {

      setError("");

      setDeletingId(accountId);


      await api.delete(
        `/aws/account/${accountId}`
      );


      alert(
        "✅ AWS Account Disconnected"
      );


      // Refresh Dashboard data
      if (onRefresh) {

        await onRefresh();

      }

    }

    catch (err) {

      console.error(
        "Delete AWS Account Error:",
        err
      );


      const message =
        err.response?.data?.detail ||
        err.response?.data?.message ||
        "Unable to disconnect AWS account.";


      setError(message);

      alert(message);

    }

    finally {

      setDeletingId(null);

    }

  };


  // ==========================================
  // PAGE
  // ==========================================

  return (

    <div className="aws-account-panel">


      {/* ======================================
          HEADER
      ====================================== */}

      <div className="aws-account-header">

        <div>

          <h2>
            Connected AWS Accounts
          </h2>

          <p>
            Manage and scan cloud environments connected
            to CloudGuardAI.
          </p>

        </div>


        <button
          className="aws-connect-button"
          onClick={() =>
            navigate("/connect-aws")
          }
        >

          + Connect AWS

        </button>

      </div>


      {/* ======================================
          ERROR
      ====================================== */}

      {
        error && (

          <div className="aws-account-error">

            ❌ {error}

          </div>

        )
      }


      {/* ======================================
          NO ACCOUNTS
      ====================================== */}

      {
        accounts.length === 0 ? (

          <div className="aws-empty-state">

            <div className="aws-empty-icon">
              AWS
            </div>


            <h3>
              No AWS Account Connected
            </h3>


            <p>
              Connect your AWS environment to start
              security scanning, risk analysis and
              compliance monitoring.
            </p>


            <button
              onClick={() =>
                navigate("/connect-aws")
              }
            >

              Connect AWS Account

            </button>

          </div>

        )

        :

        (

          <div className="aws-account-grid">

            {
              accounts.map((account) => (

                <div
                  className="aws-account-card"
                  key={account._id}
                >


                  {/* ==================================
                      CARD TOP
                  ================================== */}

                  <div className="aws-card-top">

                    <div className="aws-logo">
                      AWS
                    </div>


                    <div className="aws-status">

                      <span></span>

                      {
                        account.status ||
                        "connected"
                      }

                    </div>

                  </div>


                  {/* ==================================
                      ACCOUNT NAME
                  ================================== */}

                  <h3>

                    {
                      account.account_name ||
                      "AWS Account"
                    }

                  </h3>


                  {/* ==================================
                      ACCOUNT DETAILS
                  ================================== */}

                  <div className="aws-account-details">


                    <div>

                      <span>
                        Account ID
                      </span>

                      <strong>

                        {
                          account.aws_account_id ||
                          "N/A"
                        }

                      </strong>

                    </div>


                    <div>

                      <span>
                        Region
                      </span>

                      <strong>

                        {
                          account.region ||
                          "ap-south-1"
                        }

                      </strong>

                    </div>


                    <div className="aws-role-row">

                      <span>
                        Scanner Role
                      </span>

                      <strong>

                        {
                          account.role_arn ||
                          "N/A"
                        }

                      </strong>

                    </div>


                  </div>


                  {/* ==================================
                      ACTIONS
                  ================================== */}

                  <div className="aws-account-actions">

                    {account.status !== "connected" && (
                      <button
                        className="aws-verify-button"
                        disabled={
                          verifyingId === account._id ||
                          scanningId === account._id ||
                          deletingId === account._id
                        }
                        onClick={() =>
                          verifyConnection(account._id)
                        }
                      >
                        {
                          verifyingId === account._id
                            ? "Verifying..."
                            : "Verify STS"
                        }
                      </button>
                    )}

                    <button
                      className="aws-scan-button"
                      disabled={
                        verifyingId === account._id ||
                        scanningId === account._id ||
                        deletingId === account._id
                      }
                      onClick={() =>
                        runScan(account._id)
                      }
                    >

                      {
                        scanningId === account._id

                          ? "Scanning..."

                          : "Scan Account"
                      }

                    </button>


                    <button
                      className="aws-delete-button"
                      disabled={
                        scanningId === account._id ||
                        deletingId === account._id
                      }
                      onClick={() =>
                        removeAccount(account._id)
                      }
                    >

                      {
                        deletingId === account._id

                          ? "Disconnecting..."

                          : "Disconnect"
                      }

                    </button>


                  </div>


                </div>

              ))
            }

          </div>

        )

      }


      {/* ======================================
          ACCOUNT COUNT
      ====================================== */}

      {
        accounts.length > 0 && (

          <div className="aws-account-footer">

            <span>
              Connected Environments
            </span>

            <strong>
              {accounts.length}
            </strong>

          </div>

        )
      }


    </div>

  );

}


export default AWSAccountCard;
