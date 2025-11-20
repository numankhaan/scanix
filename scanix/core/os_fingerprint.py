TTL_VALUES = {
    "Windows": 128,
    "Linux": 64,
    "MacOS": 64,
}

def guess_os_from_ttl(ttl):
    for os, val in TTL_VALUES.items():
        if ttl == val:
            return os
    return "Unknown"