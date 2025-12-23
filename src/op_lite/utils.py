from typing import Any, Dict

def safe_get(d: Dict, *keys, default=None):
    """Nested dict safe getter: safe_get(obj, 'a', 'b') -> obj.get('a',{}).get('b')"""
    cur = d
    for k in keys:
        if not isinstance(cur, dict):
            return default
        cur = cur.get(k, default)
    return cur
