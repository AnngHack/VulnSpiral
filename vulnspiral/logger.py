import logging
import os
from logging.handlers import RotatingFileHandler

BASE_RUNS_DIR = os.path.join(os.getcwd(), "runs")

def get_run_logger(run_id: str):
    os.makedirs(BASE_RUNS_DIR, exist_ok=True)
    run_dir = os.path.join(BASE_RUNS_DIR, run_id)
    logs_dir = os.path.join(run_dir, "logs")
    os.makedirs(logs_dir, exist_ok=True)
    log_path = os.path.join(logs_dir, "run.log")
    logger = logging.getLogger(f"vulnspiral.run.{run_id}")
    if logger.handlers:
        return logger
    logger.setLevel(logging.DEBUG)
    fh = RotatingFileHandler(log_path, maxBytes=5_000_000, backupCount=3)
    fmt = logging.Formatter("%(asctime)s %(levelname)s: %(message)s")
    fh.setFormatter(fmt)
    ch = logging.StreamHandler()
    ch.setFormatter(fmt)
    logger.addHandler(fh)
    logger.addHandler(ch)
    return logger
