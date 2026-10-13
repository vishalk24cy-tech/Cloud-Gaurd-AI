from apscheduler.schedulers.background import BackgroundScheduler

from app.services.monitoring.cloud_monitor import run_cloud_monitor
from app.services.trial_service import expire_trials


# ============================================================
# CLOUDGUARDAI BACKGROUND SCHEDULER
# ============================================================

scheduler = BackgroundScheduler()


# ============================================================
# START SCHEDULER
# ============================================================

def start_scheduler():
    """
    Start all CloudGuardAI background jobs.

    Current jobs:
        1. AWS security monitoring
        2. Free-trial expiry processing
    """

    # --------------------------------------------------------
    # AWS Security Monitoring
    # --------------------------------------------------------

    scheduler.add_job(
        run_cloud_monitor,
        "interval",
        minutes=30,
        id="aws_security_monitor",
        max_instances=1,
        coalesce=True,
        replace_existing=True
    )

    # --------------------------------------------------------
    # Free Trial Expiry
    # --------------------------------------------------------

    scheduler.add_job(
        expire_trials,
        "interval",
        hours=1,
        id="free_trial_expiry",
        max_instances=1,
        coalesce=True,
        replace_existing=True
    )

    # --------------------------------------------------------
    # Start scheduler
    # --------------------------------------------------------

    if not scheduler.running:

        scheduler.start()

    print(
        "[OK] CloudGuardAI Monitoring Started"
    )

    print(
        "[OK] CloudGuardAI Trial Expiry Job Started"
    )