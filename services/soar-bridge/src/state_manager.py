import json
import os
import datetime

class StateManager:
    def __init__(self, state_file):
        self.path = state_file

    def _load(self):
        if not os.path.exists(self.path): return {}
        with open(self.path, 'r') as f: return json.load(f)

    def _save(self, data):
        with open(self.path, 'w') as f: json.dump(data, f, indent=4)

    def check_duplicate(self, ip, proc_name):
        state = self._load()
        unique_id = f"{ip}_{proc_name}" # Signature: e.g. 127.0.0.1_curl
        if unique_id in state:
            return state[unique_id]['ticket'], state[unique_id].get('count', 0)
        return None, 0

    def update_incident(self, ip, ticket_key, proc_name):
        state = self._load()
        unique_id = f"{ip}_{proc_name}"
        count = state.get(unique_id, {}).get('count', 0)
        state[unique_id] = {
            "count": count + 1,
            "ticket": ticket_key,
            "proc_signature": proc_name, # Storing the clean name
            "last_seen": str(datetime.datetime.now())
        }
        self._save(state)