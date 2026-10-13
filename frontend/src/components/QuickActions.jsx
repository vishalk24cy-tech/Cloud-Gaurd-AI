import {
    useEffect,
    useRef,
    useState
} from "react";
import { useNavigate } from "react-router-dom";
import { ClipboardList, FileText, Play, PlugZap } from "lucide-react";

import api from "../services/api";

import "./QuickActions.css";

import ScanProgressModal from "./ScanProgressModal";


function QuickActions({ onRefresh }) {

    const navigate = useNavigate();

    const [showScanner, setShowScanner] =
        useState(false);

    const [scanCompleted, setScanCompleted] =
        useState(false);

    const [scanStatus, setScanStatus] =
        useState("queued");

    const pollingRef =
        useRef(null);

    /*
     * Prevent the onboarding-triggered scan
     * from starting more than once.
     */
    const onboardingScanStarted =
        useRef(false);


    // =====================================
    // STOP JOB POLLING
    // =====================================

    const stopPolling = () => {

        if (pollingRef.current) {

            clearInterval(
                pollingRef.current
            );

            pollingRef.current = null;

        }

    };


    // =====================================
    // POLL SCAN JOB
    // =====================================

    const pollScanJob = (jobId) => {

        stopPolling();


        const checkJob = async () => {

            try {

                const response =
                    await api.get(
                        `/scan-jobs/${jobId}`
                    );


                const job =
                    response.data?.job;


                if (!job) {

                    return;

                }


                const status =
                    job.status;


                setScanStatus(
                    status
                );


                // -------------------------
                // COMPLETED
                // -------------------------

                if (
                    status ===
                    "completed"
                ) {

                    stopPolling();

                    setScanCompleted(
                        true
                    );


                    if (onRefresh) {

                        onRefresh();

                    }

                    return;

                }


                // -------------------------
                // FAILED
                // -------------------------

                if (
                    status ===
                    "failed"
                ) {

                    stopPolling();

                    setShowScanner(
                        false
                    );


                    alert(
                        job.error_message ||
                        "AWS Security Scan Failed."
                    );

                    return;

                }

            }

            catch (err) {

                console.error(
                    "Scan Job Polling Error:",
                    err
                );

            }

        };


        /*
         * Check immediately.
         */

        checkJob();


        /*
         * Continue checking every 2 seconds.
         */

        pollingRef.current =
            setInterval(
                checkJob,
                2000
            );

    };


    // =====================================
    // START AWS SCAN JOB
    // =====================================

    const runAwsScan = async () => {

        try {

            stopPolling();


            setScanCompleted(
                false
            );


            setScanStatus(
                "queued"
            );


            const accountResponse =
                await api.get(
                    "/aws/accounts"
                );


            const accounts =
                accountResponse.data?.accounts;


            if (
                !accounts ||
                accounts.length === 0
            ) {

                alert(
                    "No AWS Account Connected."
                );

                return;

            }


            const accountId =
                accounts[0]._id;


            setShowScanner(
                true
            );


            /*
             * Create asynchronous scan job.
             */

            const response =
                await api.post(
                    `/scan-jobs?account_id=${encodeURIComponent(accountId)}`
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


            setScanStatus(
                job.status ||
                "queued"
            );


            /*
             * Start polling the job.
             */

            pollScanJob(
                jobId
            );

        }

        catch (err) {

            console.error(
                "AWS Scan Job Error:",
                err
            );


            stopPolling();

            setShowScanner(
                false
            );


            alert(
                err.response?.data?.detail ||
                err.response?.data?.message ||
                err.message ||
                "AWS Scan Failed."
            );

        }

    };


    // =====================================
    // CLEANUP
    // =====================================

    useEffect(() => {

        return () => {

            stopPolling();

        };

    }, []);


    // =====================================
    // ONBOARDING FIRST-SCAN TRIGGER
    // =====================================

    useEffect(() => {

        const params =
            new URLSearchParams(
                window.location.search
            );


        const onboardingScan =
            params.get(
                "onboarding"
            );


        if (
            onboardingScan !== "scan"
        ) {

            return;

        }


        if (
            onboardingScanStarted.current
        ) {

            return;

        }


        onboardingScanStarted.current =
            true;


        /*
         * Remove the query parameter
         * immediately so refreshing the
         * dashboard does not start another scan.
         */

        window.history.replaceState(
            {},
            "",
            window.location.pathname
        );


        /*
         * Start the asynchronous scan job.
         */

        runAwsScan();

    }, []);


    // =====================================
    // =====================================
    // UI
    // =====================================

    return (

        <>

            <div className="quick-card">
                <div className="quick-grid">
                    <button type="button" className="quick-action" onClick={runAwsScan}>
                        <Play size={16} aria-hidden="true" />
                        <span>Run scan</span>
                    </button>
                    <button type="button" className="quick-action" onClick={() => navigate("/reports")}>
                        <FileText size={16} aria-hidden="true" />
                        <span>View reports</span>
                    </button>
                    <button type="button" className="quick-action" onClick={() => navigate("/settings")}>
                        <ClipboardList size={16} aria-hidden="true" />
                        <span>Manage rules</span>
                    </button>
                    <button type="button" className="quick-action" onClick={() => navigate("/connect-aws")}>
                        <PlugZap size={16} aria-hidden="true" />
                        <span>Add AWS account</span>
                    </button>
                </div>

            </div>


            <ScanProgressModal

                open={
                    showScanner
                }

                status={
                    scanStatus
                }

                completed={
                    scanCompleted
                }

                onClose={() => {

                    stopPolling();

                    setShowScanner(
                        false
                    );

                }}

                onComplete={() => {

                    setScanCompleted(
                        true
                    );

                }}

            />

        </>

    );

}


export default QuickActions;