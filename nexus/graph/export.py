import json

def to_json(result) -> str:
    # Fonction de secours pour ne pas casser l'export JSON
    try:
        return json.dumps(getattr(result, '__dict__', {}), default=str, indent=2)
    except Exception:
        return "{}"

def to_dot(result) -> str:
    lines = [
        'digraph NEXUS {',
        '  rankdir=LR;',                      # Dessine le réseau de gauche à droite
        '  bgcolor="#0D0D0D";',               # Fond noir hacker
        '  node [fontname="Courier", style="filled", fontcolor="white", color="white"];',
        '  edge [color="#555555", penwidth=2.0];',
        '  "NEXUS" [shape="Mdiamond", fillcolor="#E0115F", label="NEXUS HOST"];' # Ton PC en rouge
    ]
    
    # 1. Dessiner les machines scannées (même si aucun port n'est ouvert !)
    for target in result.targets:
        lines.append(f'  "{target}" [shape="box", fillcolor="#007BFF"];')
        lines.append(f'  "NEXUS" -> "{target}";')
        
    # 2. Dessiner les ports/services qui sont ouverts
    for svc in result.services:
        node_id = f'"{svc.address}_{svc.port}"'
        label = f"{svc.port}/{svc.protocol.upper()}\\n{svc.name}"
        lines.append(f'  {node_id} [shape="ellipse", fillcolor="#00FF41", fontcolor="black", label="{label}"];')
        lines.append(f'  "{svc.address}" -> {node_id};')
        
    lines.append('}')
    return "\n".join(lines)
