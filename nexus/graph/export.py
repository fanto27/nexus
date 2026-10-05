import json
from nexus.core.models import ScanResult

def to_json(result: ScanResult) -> str:
    nodes = [{"id": f"host:{t}", "label": t, "type": "host"} for t in result.targets]
    for s in result.services:
        nodes.append({"id": f"svc:{s.address}:{s.port}", "label": f"{s.name}/{s.port}", "type": "service"})
    edges = [{"source": f"host:{s.address}", "target": f"svc:{s.address}:{s.port}", "relation": "tcp-open"} for s in result.services]
    return json.dumps({"nodes": nodes, "edges": edges}, indent=2)

def to_dot(result: ScanResult) -> str:
    return "digraph NEXUS {}" # Version simplifiée
