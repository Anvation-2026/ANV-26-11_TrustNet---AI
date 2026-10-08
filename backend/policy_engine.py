import database as db

def violated(role, tool, params, category):
    """Return the first policy of this category that the request breaks, else None."""
    for p in db.get_policies(tool, category):
        roles = __import__("json").loads(p["allowed_roles"])
        if roles is not None and role not in roles:
            return p
        amount = params.get("amount")
        if p["max_amount"] is not None and isinstance(amount, (int, float)) and amount > p["max_amount"]:
            return p
    return None
