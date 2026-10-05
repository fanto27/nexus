import os, platform, socket, shutil

def local_snapshot():
    return {
        "platform": platform.platform(),
        "architecture": platform.machine(),
        "cpu_count": os.cpu_count(),
        "interfaces": [n for _, n in socket.if_nameindex()] if hasattr(socket, "if_nameindex") else [],
        "tools": {name: shutil.which(name) is not None for name in ("nmap", "ip", "curl")}
    }
