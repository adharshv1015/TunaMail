import os
import json
import threading

class LocalJSONStore:
    def __init__(self, filename: str):
        self.filepath = os.path.join(os.path.dirname(__file__), "..", "..", "data", filename)
        self.lock = threading.Lock()
        self._ensure_file()

    def _ensure_file(self):
        os.makedirs(os.path.dirname(self.filepath), exist_ok=True)
        if not os.path.exists(self.filepath):
            with open(self.filepath, "w") as f:
                json.dump({}, f)

    def get_all(self):
        with self.lock:
            try:
                with open(self.filepath, "r") as f:
                    return json.load(f)
            except:
                return {}

    def get(self, key: str, default=None):
        data = self.get_all()
        return data.get(key, default)

    def set(self, key: str, value):
        with self.lock:
            try:
                with open(self.filepath, "r") as f:
                    data = json.load(f)
            except:
                data = {}
            data[key] = value
            with open(self.filepath, "w") as f:
                json.dump(data, f, indent=2)

    def update(self, key: str, value_dict: dict):
        with self.lock:
            try:
                with open(self.filepath, "r") as f:
                    data = json.load(f)
            except:
                data = {}
            
            if key not in data:
                data[key] = {}
            
            if isinstance(data[key], dict):
                data[key].update(value_dict)
            else:
                data[key] = value_dict
                
            with open(self.filepath, "w") as f:
                json.dump(data, f, indent=2)

    def clear(self):
        with self.lock:
            with open(self.filepath, "w") as f:
                json.dump({}, f)

    def delete(self, key: str):
        with self.lock:
            try:
                with open(self.filepath, "r") as f:
                    data = json.load(f)
            except:
                return
            if key in data:
                del data[key]
                with open(self.filepath, "w") as f:
                    json.dump(data, f, indent=2)
