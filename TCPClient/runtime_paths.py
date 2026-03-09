import os
from datetime import datetime
from pathlib import Path


RUN_TS = datetime.now().strftime("%Y%m%d_%H%M%S")
PACKAGE_DIR = Path(__file__).resolve().parent

# Keep each run's artifacts under TCPClient/<run_timestamp>/ by default.
RUN_ROOT = Path(os.getenv("WWSN_RUN_ROOT", str(PACKAGE_DIR)))
RUN_DIR_ENV = os.getenv("WWSN_RUN_DIR", "").strip()
if RUN_DIR_ENV:
    RUN_DIR = Path(RUN_DIR_ENV).expanduser().resolve()
else:
    RUN_DIR = (RUN_ROOT / f"run_{RUN_TS}").resolve()
RUN_DIR.mkdir(parents=True, exist_ok=True)

DB_FILE = os.getenv("WWSN_DB_FILE", str((RUN_DIR / f"data_{RUN_TS}.db").resolve()))
LOG_FILE = os.getenv("WWSN_RUNTIME_LOG_FILE", str((RUN_DIR / f"server_runtime_{RUN_TS}.log").resolve()))

