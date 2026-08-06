from src.plugins.plugin_interface import Plugin


class PluginManager:
    def __init__(self) -> None:
        self._plugins: list[Plugin] = []

    def register(self, plugin: Plugin) -> None:
        self._plugins.append(plugin)

    def run_all(self) -> None:
        for plugin in self._plugins:
            plugin.run()