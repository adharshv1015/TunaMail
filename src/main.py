import sys
if hasattr(sys.stdout, 'reconfigure'):
    sys.stdout.reconfigure(encoding='utf-8')

from src.core.config import Config
from src.core.logger import get_logger

from src.analysis.analyzer import Analyzer
from src.plugins.plugin_manager import PluginManager
from src.plugins.example_plugin import ExamplePlugin

logger = get_logger(__name__)
config = Config()

def main() -> None:
    logger.info(
        f"{config.get('application', 'name')} "
        f"v{config.get('application', 'version')} Started"
    )

    manager = PluginManager()
    manager.register(ExamplePlugin())

    email_path = r"C:\Users\Asus\Downloads\[A-Kalleri_Post-Deployment-Refinement] Update_gui (PR #12).eml"
    
    analyzer = Analyzer()
    result = analyzer.analyze(email_path)

    manager.run_all()

if __name__ == "__main__":
    main()