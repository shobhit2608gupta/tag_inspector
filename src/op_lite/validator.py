from pydantic import BaseModel, ValidationError
from typing import Optional, Any, Dict

class DataLayerSchema(BaseModel):
    page_category: str
    page_type: str
    user_logged_in: bool
    customer_id: Optional[str] = None

def normalize_datalayer_obj(obj: Dict[str, Any]) -> Dict[str, Any]:
    # Try common key patterns
    normalized = {
        "page_category": (obj.get("page", {}) or {}).get("category") or obj.get("page_category") or obj.get("pageCategory"),
        "page_type": (obj.get("page", {}) or {}).get("type") or obj.get("page_type") or obj.get("pageType"),
        "user_logged_in": (obj.get("user", {}) or {}).get("loggedIn") or obj.get("user_logged_in") or obj.get("userLoggedIn"),
        "customer_id": (obj.get("user", {}) or {}).get("id") or obj.get("customerId") or obj.get("customer_id")
    }
    return normalized

def validate_datalayer(dl_snapshot) -> Dict[str, Any]:
    if not dl_snapshot:
        return {"valid": False, "errors": ["no dataLayer"]}
    obj = None
    if isinstance(dl_snapshot, list) and len(dl_snapshot) > 0:
        for item in reversed(dl_snapshot):
            if isinstance(item, dict):
                obj = item
                break
    elif isinstance(dl_snapshot, dict):
        obj = dl_snapshot

    if not obj:
        return {"valid": False, "errors": ["no dict found in dataLayer"]}

    normalized = normalize_datalayer_obj(obj)
    try:
        DataLayerSchema(**normalized)
        return {"valid": True, "errors": [], "normalized": normalized}
    except ValidationError as e:
        return {"valid": False, "errors": e.errors(), "normalized": normalized}
