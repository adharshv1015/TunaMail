import json
from pathlib import Path
from typing import Any


class Config:
    _instance = None

    def __new__(cls):
        if cls._instance is None:
            cls._instance = super().__new__(cls)

            config_file = Path("config/settings.json")

            with open(config_file, "r", encoding="utf-8") as file:
                cls._instance.data = json.load(file)

        return cls._instance

    def get(self, *keys: str) -> Any:
        value = self.data

        for key in keys:
            value = value[key]

        return value