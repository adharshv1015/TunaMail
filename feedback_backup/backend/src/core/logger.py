import logging
from pathlib import Path


_LOGGER_INITIALIZED = False


def get_logger(name: str) -> logging.Logger:
    global _LOGGER_INITIALIZED

    log_dir = Path("logs")
    log_dir.mkdir(exist_ok=True)

    log_file = log_dir / "tunamail.log"

    logger = logging.getLogger(name)

    if not _LOGGER_INITIALIZED:
        formatter = logging.Formatter(
            "%(asctime)s | %(levelname)s | %(message)s",
            "%Y-%m-%d %H:%M:%S",
        )

        console_handler = logging.StreamHandler()
        console_handler.setFormatter(formatter)

        file_handler = logging.FileHandler(log_file, encoding="utf-8")
        file_handler.setFormatter(formatter)

        root_logger = logging.getLogger()
        root_logger.setLevel(logging.INFO)
        root_logger.addHandler(console_handler)
        root_logger.addHandler(file_handler)

        _LOGGER_INITIALIZED = True

    return logger