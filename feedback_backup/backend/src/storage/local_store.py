import os
import json
import logging
import threading
import tempfile
import time

logger = logging.getLogger(__name__)

class LocalJSONStore:
    def __init__(self, filename: str):
        self.filepath = os.path.join(os.path.dirname(__file__), "..", "..", "data", filename)
        self.lock = threading.RLock()
        self._cache = None
        self._last_loaded = 0
        self._ensure_file()

    def _ensure_file(self):
        try:
            os.makedirs(os.path.dirname(self.filepath), exist_ok=True)
            if not os.path.exists(self.filepath) or os.path.getsize(self.filepath) == 0:
                with self.lock:
                    with open(self.filepath, "w") as f:
                        json.dump({}, f)
        except Exception as e:
            logger.warning("LocalJSONStore: could not initialise %s: %s", self.filepath, e)

    def _load(self):
        # Must be called with lock acquired
        if self._cache is not None:
            return self._cache
        try:
            if not os.path.exists(self.filepath) or os.path.getsize(self.filepath) == 0:
                self._cache = {}
                return self._cache
            with open(self.filepath, "r") as f:
                data = json.load(f)
                if not isinstance(data, dict):
                    logger.warning(
                        "LocalJSONStore: %s contained non-dict data (%s) — resetting to empty",
                        self.filepath, type(data).__name__
                    )
                    data = {}
                self._cache = data
                self._last_loaded = time.time()
                return self._cache
        except json.JSONDecodeError as e:
            logger.error(
                "LocalJSONStore: corrupted JSON in %s (%s) — using empty fallback",
                self.filepath, e
            )
            self._cache = {}
            return self._cache
        except Exception as e:
            logger.error("LocalJSONStore: failed to load %s: %s", self.filepath, e)
            self._cache = {}
            return self._cache

    def _atomic_write(self, data):
        # Must be called with lock acquired
        try:
            dir_name = os.path.dirname(self.filepath)
            os.makedirs(dir_name, exist_ok=True)
            fd, tmp_path = tempfile.mkstemp(dir=dir_name, prefix=".tmp_")
            with os.fdopen(fd, "w") as f:
                json.dump(data, f, indent=2)
                f.flush()
                os.fsync(f.fileno())
            os.replace(tmp_path, self.filepath)
            self._cache = data
        except Exception as e:
            logger.error("LocalJSONStore: atomic write to %s failed: %s", self.filepath, e)
            if 'tmp_path' in locals() and os.path.exists(tmp_path):
                try:
                    os.remove(tmp_path)
                except Exception:
                    pass

    def get_all(self):
        with self.lock:
            return dict(self._load())

    def get(self, key: str, default=None):
        with self.lock:
            data = self._load()
            return data.get(key, default)

    def set(self, key: str, value):
        with self.lock:
            data = self._load()
            data[key] = value
            self._atomic_write(data)

    def update(self, key: str, value_dict: dict):
        with self.lock:
            data = self._load()
            if key not in data:
                data[key] = {}
            
            if isinstance(data[key], dict) and isinstance(value_dict, dict):
                data[key].update(value_dict)
            else:
                data[key] = value_dict
                
            self._atomic_write(data)

    def clear(self):
        with self.lock:
            self._atomic_write({})

    def delete(self, key: str):
        with self.lock:
            data = self._load()
            if key in data:
                del data[key]
                self._atomic_write(data)
