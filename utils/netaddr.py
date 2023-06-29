import hashlib

def localaddr_from_netaddr(netaddr) -> str:
    # Compute the MD5 hash of the network address
    return hashlib.md5(str(netaddr).encode()).hexdigest()