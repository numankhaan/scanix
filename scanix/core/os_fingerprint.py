"""OS identification is unimplemented until remote packet fingerprinting exists."""


def guess_os_from_ttl(ttl):
    """Compatibility helper; a TTL alone cannot identify an operating system."""
    return None
