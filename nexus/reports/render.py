from __future__ import annotations

import html
import json
from dataclasses import asdict

from nexus.core.models import ScanResult
from nexus.core.scoring import exposure_index


def _report_data(
    result: ScanResult,
    actions: list[dict[str, object]],
) -> dict[str, object]:
    index = exposure_index(result.services)
    responsive = sorted({service.address for service in result.services})

    return {
        "schema_version": "1.0",
        "executive_summary": (
            f"{len(result.targets)} cible(s) examinée(s), "
            f"{len(responsive)} adresse(s) ayant répondu sur les ports testés, "
            f"{len(result.services)} service(s) TCP observé(s) et "
            f"{len(result.findings)} finding(s) émis."
        ),
        "scan": {
            "id": result.scan_id,
            "started_at": result.started_at,
            "duration_seconds": result.duration_seconds,
            "status": result.status,
            "ports": result.ports,
        },
        "targets": result.targets,
        "hosts_with_open_tcp": responsive,
        "services": [asdict(item) for item in result.services],
        "findings": [asdict(item) for item in result.findings],
        "risk": asdict(index),
        "recommendations": [
            (
                "Vérifier que chaque service observé est attendu et limité "
                "aux réseaux qui en ont besoin."
            )
        ] if result.services else [],
        "timeline": [
            {
                "at": result.started_at,
                "event": "Scan terminé",
                "duration_seconds": result.duration_seconds,
            }
        ],
        "actions_performed": actions,
        "limitations": [
            "Un port ouvert n'est pas une vulnérabilité.",
            "Les versions ne sont pas déterminées par ce scanner.",
            "L'absence de finding ne constitue pas une preuve d'absence de vulnérabilité.",
        ],
    }


def _markdown(data: dict[str, object]) -> str:
    services = data["services"]
    findings = data["findings"]
    assert isinstance(services, list)
    assert isinstance(findings, list)

    lines = [
        "# NEXUS — Rapport",
        "",
        "## Executive Summary",
        "",
        str(data["executive_summary"]),
        "",
        "## Targets",
        "",
    ]

    for target in data["targets"]:  # type: ignore[union-attr]
        lines.append(f"- `{target}`")

    lines += [
        "",
        "## Services",
        "",
        "| Adresse | Port | Proto | Service | Version | TLS |",
        "|---|---:|---|---|---|---|",
    ]

    for item in services:
        assert isinstance(item, dict)
        version = item.get("version") or "non déterminée"
        tls = item.get("tls")
        tls_value = "inconnu" if tls is None else str(tls)
        lines.append(
            f"| {item['address']} | {item['port']} | {item['protocol']} "
            f"| {item['name']} | {version} | {tls_value} |"
        )

    lines += ["", "## Findings", ""]
    if findings:
        for item in findings:
            assert isinstance(item, dict)
            lines += [
                f"### [{item['severity']}] {item['title']}",
                "",
                f"- **What:** {item['what']}",
                f"- **Why:** {item['why']}",
                f"- **Evidence:** {item['evidence']}",
                f"- **Impact:** {item['impact']}",
                f"- **Recommendation:** {item['recommendation']}",
                f"- **Confidence:** {item['confidence']:.0%}",
                "",
            ]
    else:
        lines.append(
            "Aucun finding n'a été émis par les modules actifs. "
            "Ce résultat ne signifie pas qu'aucune vulnérabilité n'existe."
        )

    risk = data["risk"]
    assert isinstance(risk, dict)
    lines += [
        "",
        "## Risk / Exposure",
        "",
        f"**Exposure Index : {risk['score']}/100**",
        "",
        str(risk["caveat"]),
        "",
        "## Recommendations",
        "",
    ]
    lines.extend(f"- {item}" for item in data["recommendations"])  # type: ignore[union-attr]

    lines += [
        "",
        "## Timeline",
        "",
        f"- Début : {data['scan']['started_at']}",  # type: ignore[index]
        f"- Durée : {data['scan']['duration_seconds']:.2f} s",  # type: ignore[index]
        "",
        "## Actions performed",
        "",
    ]

    actions = data["actions_performed"]
    assert isinstance(actions, list)
    if not actions:
        lines.append("Aucune action intrusive enregistrée.")
    else:
        for action in actions:
            lines.append(f"- `{action['status']}` — {action['action']} sur {action['target']}")

    lines += ["", "## Limitations", ""]
    lines.extend(f"- {item}" for item in data["limitations"])  # type: ignore[union-attr]
    return "\n".join(lines) + "\n"


def _html(data: dict[str, object]) -> str:
    esc = lambda value: html.escape(str(value), quote=True)
    services = data["services"]
    findings = data["findings"]
    assert isinstance(services, list)
    assert isinstance(findings, list)

    service_rows = "".join(
        "<tr>"
        f"<td>{esc(item['address'])}</td>"
        f"<td>{esc(item['port'])}</td>"
        f"<td>{esc(item['protocol'])}</td>"
        f"<td>{esc(item['name'])}</td>"
        f"<td>{esc(item.get('version') or 'non déterminée')}</td>"
        "</tr>"
        for item in services
    )

    finding_rows = "".join(
        "<li>"
        f"<strong>{esc(item['severity'])} — {esc(item['title'])}</strong>"
        f"<p>{esc(item['what'])}</p>"
        f"<p><b>Evidence:</b> {esc(item['evidence'])}</p>"
        f"<p><b>Recommendation:</b> {esc(item['recommendation'])}</p>"
        "</li>"
        for item in findings
    ) or "<li>Aucun finding émis par les modules actifs.</li>"

    targets = data["targets"]
    assert isinstance(targets, list)
    target_list = "".join(f"<li><code>{esc(value)}</code></li>" for value in targets)

    risk = data["risk"]
    assert isinstance(risk, dict)

    return f"""<!doctype html>
<html lang="fr">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>NEXUS — Rapport</title>
<style>
body {{ font: 16px/1.5 system-ui, sans-serif; max-width: 1000px;
       margin: 2rem auto; padding: 0 1rem; color: #18212b; }}
h1, h2 {{ color: #087f8c; }}
table {{ border-collapse: collapse; width: 100%; }}
th, td {{ border: 1px solid #ccd5dd; padding: .5rem; text-align: left; }}
th {{ background: #eef4f6; }}
.notice {{ background: #fff5d6; padding: 1rem; }}
</style>
</head>
<body>
<h1>NEXUS — Rapport</h1>
<h2>Executive Summary</h2>
<p>{esc(data['executive_summary'])}</p>
<h2>Targets</h2><ul>{target_list}</ul>
<h2>Services</h2>
<table><thead><tr><th>Adresse</th><th>Port</th><th>Proto</th>
<th>Service</th><th>Version</th></tr></thead>
<tbody>{service_rows}</tbody></table>
<h2>Findings</h2><ul>{finding_rows}</ul>
<h2>Exposure Index</h2>
<p><strong>{esc(risk['score'])}/100</strong> — {esc(risk['caveat'])}</p>
<p class="notice">Un port ouvert n'est pas une vulnérabilité. L'absence de finding
ne prouve pas l'absence de vulnérabilité.</p>
<h2>Actions enregistrées</h2>
<pre>{esc(json.dumps(data['actions_performed'], indent=2, ensure_ascii=False))}</pre>
</body></html>
"""


def render_report(
    result: ScanResult,
    *,
    fmt: str,
    actions: list[dict[str, object]] | None = None,
) -> str:
    data = _report_data(result, actions or [])

    if fmt == "json":
        return json.dumps(data, indent=2, ensure_ascii=False) + "\n"
    if fmt == "markdown":
        return _markdown(data)
    if fmt == "html":
        return _html(data)

    raise ValueError(f"Format de rapport non pris en charge : {fmt}")
