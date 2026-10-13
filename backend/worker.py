from app.services.scan_worker import run_background_worker


if __name__ == "__main__":
    print("[SCAN-WORKER] Standalone worker process starting...")
    run_background_worker()