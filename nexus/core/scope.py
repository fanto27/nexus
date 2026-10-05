from __future__ import annotations
import ipaddress
import socket
from collections.abc import Iterable

DEFAULT_PORTS = (21, 22, 23, 25, 53, 80, 111, 135, 139, 443, 445, 993, 995, 1433, 1521, 3306, 3389, 5432, 5900, 6379, 8080, 8443, 9200)
DEFAULT_PORTS_CSV = ",".join(str(port) for port in DEFAULT_PORTS)

class ScopeError(ValueError): pass

def parse_ports(spec: str) -> list[int]:
    ports: set[int] = set()
    for raw_part in spec.split(","):
        part = raw_part.strip()
        if not part: continue
        if "-" in part:
            start, end = map(int, part.split("-", 1))
            ports.update(range(start, end + 1))
        else:
            ports.add(int(part))
    return sorted(ports)

def expand_targets(raw_targets: Iterable[str], *, offline: bool = False, max_hosts: int = 256) -> list[str]:
    resolved: set[str] = set()
    for item in raw_targets:
        item = item.strip()
        if not item: continue
        if "/" in item:
            network = ipaddress.ip_network(item, strict=False)
            resolved.update(str(addr) for addr in network.hosts())
        else:
            try:
                resolved.add(str(ipaddress.ip_address(item)))
            except ValueError:
                records = socket.getaddrinfo(item, None, type=socket.SOCK_STREAM)
                resolved.update(record[4][0] for record in records)
    return sorted(list(resolved)[:max_hosts])

def is_local_scope(addresses: Iterable[str]) -> bool:
    return all(ipaddress.ip_address(ip).is_private or ipaddress.ip_address(ip).is_loopback for ip in addresses)
