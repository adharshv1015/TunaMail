from .local_store import LocalJSONStore

class CampaignStore:
    def __init__(self):
        self.store = LocalJSONStore("campaigns.json")
        
    def get_all_campaigns(self):
        return self.store.get_all()

    def get_campaign(self, campaign_id: str):
        return self.store.get(campaign_id, None)

    def update_campaign(self, campaign_id: str, campaign_data: dict):
        self.store.set(campaign_id, campaign_data)

_campaign_store = None
def get_campaign_store() -> CampaignStore:
    global _campaign_store
    if _campaign_store is None:
        _campaign_store = CampaignStore()
    return _campaign_store
