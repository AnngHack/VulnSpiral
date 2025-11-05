import os

try:
    import netifaces
except Exception:
    netifaces = None

def list_interfaces():
    if netifaces:
        try:
            return list(netifaces.interfaces())
        except Exception:
            pass
    # Fallback to sysfs (Linux)
    sysfs = "/sys/class/net"
    try:
        return sorted([d for d in os.listdir(sysfs) if os.path.isdir(os.path.join(sysfs, d))])
    except Exception:
        return ["lo", "eth0", "wlan0"]

def get_iface_ipv4(iface: str):
    """Return first IPv4 address on iface (string) or None."""
    if not netifaces:
        return None
    try:
        addrs = netifaces.ifaddresses(iface)
        if netifaces.AF_INET in addrs:
            ip = addrs[netifaces.AF_INET][0].get("addr")
            return ip
    except Exception:
        return None
    return None

def validate_interface(iface: str) -> bool:
    return iface in list_interfaces()
