from src.core.logger import get_logger
from src.plugins.plugin_interface import Plugin

logger = get_logger(__name__)


class ExamplePlugin(Plugin):

    @property
    def name(self) -> str:
        return "Example Plugin"

    def run(self) -> None:
        logger.info(f"{self.name} executed successfully.")