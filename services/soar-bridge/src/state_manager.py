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

    def check_duplicate(self, ip):
        state = self._load()
        if ip in state:
            return state[ip]['ticket'], state[ip]['count']
        return None, 0

    def update_incident(self, ip, ticket_key):
        state = self._load()
        count = state.get(ip, {}).get('count', 0)
        state[ip] = {
            "count": count + 1,
            "ticket": ticket_key,
            "last_seen": str(datetime.datetime.now())
        }
        self._save(state)