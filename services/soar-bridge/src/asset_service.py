import pandas as pd
from datetime import datetime
import pytz

class AssetService:
    def __init__(self, csv_path):
        self.path = csv_path
        self.timezone = pytz.timezone("Asia/Dubai")

    def get_context(self, ip):
        try:
            df = pd.read_csv(self.path)
            asset = df[df['ip_address'] == ip]
            
            if asset.empty:
                return {"criticality": "Standard", "is_business_hours": True, "owner": "Unknown"}

            asset_data = asset.iloc[0]
            
            # Logic to check business hours (e.g., 0800-1800)
            now = datetime.now(self.timezone).hour
            is_work_time = 8 <= now <= 18

            return {
                "hostname": asset_data['hostname'],
                "criticality": asset_data['criticality'],
                "owner": asset_data['owner'],
                "department": asset_data['department'],
                "is_business_hours": is_work_time
            }
        except Exception:
            return {"criticality": "Standard", "is_business_hours": True}