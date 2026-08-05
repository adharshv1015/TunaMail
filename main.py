from src.core.logger import get_logger


logger = get_logger(__name__)


def main() -> None:
    logger.info("Platform Started")


if __name__ == "__main__":
    main()