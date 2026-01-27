import requests, os, base64
from dotenv import load_dotenv
load_dotenv()
# Replace with your actual recent ticket ID like KAN-60
issue_key = "KAN-60" 
url = f"{os.getenv('JIRA_URL')}/rest/api/2/issue/{issue_key}/transitions"
auth_header = base64.b64encode(f"{os.getenv('JIRA_USER_EMAIL')}:{os.getenv('JIRA_API_TOKEN')}".encode()).decode()
r = requests.get(url, headers={"Authorization": f"Basic {auth_header}"})
for t in r.json().get('transitions', []):
    print(f"ID: {t['id']} -> {t['to']['name']}")