import requests, os, base64
from dotenv import load_dotenv

# Since this script is IN THE ROOT, .env is right here.
load_dotenv() 

def get_analyst_id(email_to_search):
    url = os.getenv('JIRA_URL')
    user = os.getenv('JIRA_USER_EMAIL')
    token = os.getenv('JIRA_API_TOKEN')

    if not url:
        print("[!] ERROR: JIRA_URL is None. Make sure you are running in the root folder with a valid .env")
        return

    # Set up the Search URL
    search_url = f"{url}/rest/api/2/user/search?query={email_to_search}"
    
    # Auth setup
    auth_header = base64.b64encode(f"{user}:{token}".encode()).decode()

    headers = {
        "Authorization": f"Basic {auth_header}",
        "Accept": "application/json"
    }

    try:
        r = requests.get(search_url, headers=headers)
        data = r.json()

        if data and len(data) > 0:
            print(f"\n✅ SUCCESS! HUMAN ANALYST FOUND")
            print(f"Name: {data[0]['displayName']}")
            print(f"AccountId: {data[0]['accountId']}")
        else:
            print(f"\n[!] ERROR: User '{email_to_search}' not found in site: {url}")
            print("Check if you accepted the invite and if the email is exact.")
    except Exception as e:
        print(f"[!] Request failed: {e}")

if __name__ == "__main__":
    get_analyst_id("nifunaif612181@hotmail.com")