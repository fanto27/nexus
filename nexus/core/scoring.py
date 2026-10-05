from __future__ import annotations
from dataclasses import dataclass
from nexus.core.models import Service

_EXTRA_EXPOSURE = {23: 8, 445: 4, 3306: 3, 3389: 4, 5432: 3, 6379: 4, 9200: 4}

@dataclass(frozen=True, slots=True)
class ScoreLoss:
    label: str
    points: int
    evidence: str

@dataclass(frozen=True, slots=True)
class ExposureIndex:
    score: int
    deductions: tuple[ScoreLoss, ...]
    caveat: str = "Indice heuristique basé sur les ports TCP observés."

def exposure_index(services: list[Service]) -> ExposureIndex:
    unique = {(s.address, s.protocol, s.port): s for s in services}
    deductions = [
        ScoreLoss(f"{s.address} — {s.protocol}/{s.port}", 1 + _EXTRA_EXPOSURE.get(s.port, 0), "Connexion établie.")
        for s in unique.values()
    ]
    score = max(0, 100 - sum(item.points for item in deductions))
    return ExposureIndex(score=score, deductions=tuple(deductions))
