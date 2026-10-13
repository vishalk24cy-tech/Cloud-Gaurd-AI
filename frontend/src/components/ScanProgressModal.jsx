import "./ScanProgressModal.css";


function ScanProgressModal({

    open,

    status = "queued",

    completed = false,

    onClose,

    onComplete

}) {

    const steps = [

        "Initializing AWS Connection",

        "Checking IAM Policies",

        "Scanning EC2 Instances",

        "Analyzing S3 Buckets",

        "Checking Lambda Functions",

        "Reviewing CloudTrail",

        "Generating AI Security Analysis"

    ];


    if (!open) {

        return null;

    }


    // =====================================
    // REAL JOB STATUS
    // =====================================

    const normalizedStatus =
        String(status || "queued")
            .toLowerCase();


    const isQueued =
        normalizedStatus === "queued";

    const isRunning =
        normalizedStatus === "running";

    const isRetrying =
        normalizedStatus === "retrying";

    const isCompleted =
        normalizedStatus === "completed" ||
        completed;

    const isFailed =
        normalizedStatus === "failed";


    // =====================================
    // PROGRESS
    // =====================================

    let progress = 10;

    let currentStep = 0;


    if (isQueued) {

        progress = 10;
        currentStep = 0;

    }


    else if (isRunning) {

        progress = 55;
        currentStep = 3;

    }


    else if (isRetrying) {

        progress = 45;
        currentStep = 2;

    }


    else if (isCompleted) {

        progress = 100;
        currentStep = steps.length - 1;

    }


    else if (isFailed) {

        progress = 100;
        currentStep = 0;

    }


    // =====================================
    // STATUS TEXT
    // =====================================

    let statusText =
        "Preparing security scan...";


    if (isQueued) {

        statusText =
            "Scan job queued. Waiting for worker...";

    }


    if (isRunning) {

        statusText =
            "AWS security scan is running...";

    }


    if (isRetrying) {

        statusText =
            "Scan is being retried...";

    }


    if (isCompleted) {

        statusText =
            "AWS security scan completed.";

    }


    if (isFailed) {

        statusText =
            "AWS security scan failed.";

    }


    // =====================================
    // UI
    // =====================================

    return (

        <div className="scan-overlay">

            <div className="scan-modal">

                <h2>
                    CloudGuardAI Enterprise Scanner
                </h2>


                <p>
                    {statusText}
                </p>


                <div className="progress-bar">

                    <div

                        className="progress-fill"

                        style={{
                            width: `${progress}%`
                        }}

                    />

                </div>


                <div className="progress-text">

                    {progress}%

                </div>


                <div className="scan-steps">

                    {

                        steps.map(
                            (step, index) => {

                                const stepCompleted =
                                    isCompleted ||
                                    index < currentStep;

                                const stepActive =
                                    !isCompleted &&
                                    !isFailed &&
                                    index === currentStep;


                                return (

                                    <div

                                        key={index}

                                        className={`scan-step ${
                                            stepCompleted
                                                ? "completed"
                                                : stepActive
                                                ? "active"
                                                : ""
                                        }`}

                                    >

                                        <div className="step-icon">

                                            {

                                                stepCompleted

                                                    ? "✓"

                                                    : stepActive

                                                    ? "●"

                                                    : "○"

                                            }

                                        </div>


                                        <div className="step-content">

                                            <span>
                                                {step}
                                            </span>

                                        </div>

                                    </div>

                                );

                            }

                        )

                    }

                </div>


                {/* =================================
                    COMPLETED
                ================================= */}

                {

                    isCompleted &&

                    <div className="scan-success">

                        <h3>
                            Scan Completed Successfully
                        </h3>

                        <p>
                            AI Security Analysis Generated
                        </p>

                        <button

                            onClick={() => {

                                if (onComplete) {

                                    onComplete();

                                }

                                if (onClose) {

                                    onClose();

                                }

                            }}

                            className="close-btn"

                        >

                            View Results

                        </button>

                    </div>

                }


                {/* =================================
                    FAILED
                ================================= */}

                {

                    isFailed &&

                    <div className="scan-success">

                        <h3>
                            Scan Failed
                        </h3>

                        <p>
                            The scan worker could not complete
                            this AWS security scan.
                        </p>

                        <button

                            onClick={onClose}

                            className="close-btn"

                        >

                            Close

                        </button>

                    </div>

                }

            </div>

        </div>

    );

}


export default ScanProgressModal;