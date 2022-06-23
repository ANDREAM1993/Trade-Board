from hashlib import md5

def string_safe(string=None):
    try:
        if isinstance(string, str):
            return {"state": True, "hash": md5(string.encode()).hexdigest()}
        return {
            "state": False,
            "title": "Security Error",
            "text": "Invalid Type of Entry Value"
        }
    except:
        return {
            "state": False,
            "title": "Security Error",
            "text": "Unknown Error with Entry Value"
        }