from __future__ import annotations

import argparse
import asyncio
import ipaddress
import json
import os
import sqlite3
import sys
from datetime import datetime, timezone
from pathlib import Path
from time import monotonic

from rich.console import Console
from rich.panel import Panel
from rich.progress import (
    BarColumn,
    Progress,
    SpinnerColumn,
    TaskProgressColumn,
    TextColumn,
)
from rich.table import Table
from rich.text import Text

from nexus import __version__
from nexus.audit.local import local_snapshot
from nexus.core.models import ScanResult
from nexus.core.scope import (
    DEFAULT_PORTS_CSV,
    ScopeError,
    expand_targets,
    is_local_scope,
    parse_ports,
)
from nexus.core.scoring import exposure_index
from nexus.core.store import Store
from nexus.graph.export import to_dot, to_json
from nexus.plugins.api import BUILTIN_CATALOG
from nexus.reports.render import render_report
from nexus.scanners.tcp import scan_tcp

# --- NOUVEAU : Importation de l'ActionGate ---
from nexus.core.gate import gate, ActionRequest

console = Console()

def _add_child_mode_flags(parser: argparse.ArgumentParser) -> None:
    group = parser.add_mutually_exclusive_group()
    group.add_argument("--safe", dest="mode", action="store_const", const="safe", default=argparse.SUPPRESS, help="Interdire les actions intrusives.")
    group.add_argument("--authorized", dest="mode", action="store_const", const="authorized", default=argparse.SUPPRESS, help="Autorisation explicite.")
    parser.add_argument("--lab", action="store_true", default=argparse.SUPPRESS, help="Restreindre aux adresses locales.")
    parser.add_argument("--offline", action="store_true", default=argparse.SUPPRESS, help="Interdire DNS.")
    parser.add_argument("--db", type=Path, default=argparse.SUPPRESS, help="Chemin SQLite.")

def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="nexus", description="NEXUS — framework local d'audit et de sécurité")
    parser.add_argument("--version", action="version", version=f"NEXUS {__version__}")
    root_mode = parser.add_mutually_exclusive_group()
    root_mode.add_argument("--safe", dest="mode", action="store_const", const="safe")
    root_mode.add_argument("--authorized", dest="mode", action="store_const", const="authorized")
    parser.set_defaults(mode="safe", lab=False, offline=False, db=None)
    parser.add_argument("--lab", action="store_true")
    parser.add_argument("--offline", action="store_true")
    parser.add_argument("--db", type=Path)
    commands = parser.add_subparsers(dest="command")

    scan = commands.add_parser("scan")
    _add_child_mode_flags(scan)
    scan.add_argument("targets", nargs="*")
    scan.add_argument("-t", "--target", dest="targets_option", nargs="+")
    scan.add_argument("--ports", default=DEFAULT_PORTS_CSV)
    scan.add_argument("--timeout", type=float, default=0.6)
    scan.add_argument("--concurrency", type=int, default=128)

    map_parser = commands.add_parser("map")
    map_parser.add_argument("--scan-id", default="latest")
    map_parser.add_argument("--format", choices=("json", "dot"), default="json")
    map_parser.add_argument("--output", type=Path)

    report = commands.add_parser("report")
    report.add_argument("--scan-id", default="latest")
    report.add_argument("--format", choices=("json", "markdown", "html"), default="markdown")
    report.add_argument("--output", type=Path)

    audit = commands.add_parser("audit")
    audit_commands = audit.add_subparsers(dest="audit_command", required=True)
    local = audit_commands.add_parser("local")
    local.add_argument("--format", choices=("table", "json"), default="table")

    plugins = commands.add_parser("plugins")
    plugin_commands = plugins.add_subparsers(dest="plugin_command")
    plugin_info = plugin_commands.add_parser("info")
    plugin_info.add_argument("name")
    return parser

def _load_scan(store: Store, scan_id: str) -> ScanResult:
    selected_id = store.latest_scan_id() if scan_id == "latest" else scan_id
    if selected_id is None: raise ValueError("Aucun scan enregistré")
    result = store.load_scan(selected_id)
    if result is None: raise ValueError(f"Scan inconnu : {selected_id}")
    return result

def _dashboard(store: Store) -> None:
    scan_id = store.latest_scan_id()
    if scan_id is None:
        console.print(Panel("STATUS     IDLE\nTARGET     —\nHOSTS      0\nSERVICES   0\nFINDINGS   0", title="Dashboard", border_style="blue"))
        return
    result = _load_scan(store, scan_id)
    score = exposure_index(result.services)
    responsive = len({service.address for service in result.services})
    console.print(Panel(f"SCAN ID    {result.scan_id}\nSTATUS     {result.status.upper()}\nTARGETS    {len(result.targets)}\nRESPONSES  {responsive}\nSERVICES   {len(result.services)}\nFINDINGS   {len(result.findings)}\nEXPOSURE   {score.score}/100", title="Dernier scan", border_style="cyan"))

def _render_scan(result: ScanResult) -> None:
    score = exposure_index(result.services)
    responsive = len({service.address for service in result.services})
    console.print(Panel(f"ID         {result.scan_id}\nTARGETS    {len(result.targets)}\nRESPONSES  {responsive}\nSERVICES   {len(result.services)}\nEXPOSURE   {score.score}/100", title="NEXUS — Scan terminé", border_style="green"))
    table = Table(title="Services TCP observés")
    table.add_column("Adresse", style="cyan")
    table.add_column("Port", justify="right")
    table.add_column("Protocole")
    table.add_column("Service")
    table.add_column("Version")
    for service in result.services:
        table.add_row(service.address, str(service.port), service.protocol, service.name, service.version or "non déterminée")
    if result.services: console.print(table)
    else: console.print("Aucun port ouvert observé.")

def _confirm_scan(targets: list[str], ports: list[int], *, mode: str) -> None:
    if not sys.stdin.isatty(): raise PermissionError("Le consentement interactif est obligatoire.")
    preview = ", ".join(targets[:8]) + (f", … (+{len(targets) - 8})" if len(targets) > 8 else "")
    body = Text()
    body.append(f"Cibles : {preview}\nPorts   : {len(ports)}\nSondes  : {len(targets) * len(ports)}")
    console.print(Panel(body, title="Portée demandée", border_style="yellow"))
    if mode == "authorized":
        if console.input("Attestez-vous disposer d'une autorisation ? Tapez \"I AM AUTHORIZED\" : ").strip() != "I AM AUTHORIZED":
            raise PermissionError("Attestation refusée")
    expected = f"SCAN {len(targets)}"
    if console.input(f'Tapez exactement "{expected}" pour lancer : ').strip() != expected:
        raise PermissionError("Scan annulé")

def _write_private(path: Path, content: str) -> None:
    path = path.expanduser()
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8")
    try: path.chmod(0o600)
    except OSError: pass

def _run_scan(args: argparse.Namespace, store: Store) -> None:
    raw_targets = list(args.targets)
    if args.targets_option: raw_targets.extend(args.targets_option)
    if not raw_targets: raise ScopeError("Indiquer une cible.")
    addresses = expand_targets(raw_targets, offline=args.offline, max_hosts=256)
    ports = parse_ports(args.ports)
    
    _confirm_scan(addresses, ports, mode=args.mode)
    
    # --- NOUVEAU : Le garde du corps contrôle l'action ---
    for address in addresses:
        req = ActionRequest(
            module="cli.scan",
            capability="network.connect",
            target=address,
            mode=args.mode
        )
        if not gate.check(req):
            raise PermissionError(f"ActionGate a formellement interdit le scan vers {address}.")
    # -----------------------------------------------------

    started = datetime.now(timezone.utc).isoformat()
    timer = monotonic()
    with Progress(SpinnerColumn(), TextColumn("[progress.description]{task.description}"), BarColumn(), TaskProgressColumn(), console=console) as progress:
        task = progress.add_task("Sondes TCP", total=len(addresses) * len(ports))
        services = asyncio.run(scan_tcp(addresses, ports, timeout=args.timeout, concurrency=args.concurrency, progress=lambda d, t: progress.update(task, completed=d)))
    result = ScanResult(targets=addresses, ports=ports, services=services, started_at=started, duration_seconds=monotonic() - timer)
    store.save_scan(result, mode=args.mode)
    _render_scan(result)

def _run_map(args: argparse.Namespace, store: Store) -> None:
    result = _load_scan(store, args.scan_id)
    content = to_json(result) if args.format == "json" else to_dot(result)
    if args.output:
        _write_private(args.output, content)
        console.print(f"Graphe écrit dans {args.output}")
    else: sys.stdout.write(content)

def _run_report(args: argparse.Namespace, store: Store) -> None:
    result = _load_scan(store, args.scan_id)
    try:
        actions = store.list_actions(result.scan_id)
    except Exception:
        actions = []
        
    content = render_report(result, fmt=args.format, actions=actions)
    if args.output:
        _write_private(args.output, content)
        console.print(f"Rapport écrit dans {args.output}")
    else: sys.stdout.write(content)

def _run_local_audit(fmt: str) -> None:
    snapshot = local_snapshot()
    if fmt == "json":
        sys.stdout.write(json.dumps(snapshot, indent=2, ensure_ascii=False) + "\n")
        return
    table = Table(title="Audit local")
    table.add_column("Champ", style="cyan")
    table.add_column("Valeur")
    
    for key, value in snapshot.items():
        table.add_row(str(key), str(value))
        
    console.print(table)

def _interactive_menu(store: Store) -> None:
    """Menu façon Red Tiger en ASCII Art et interface interactive"""
    while True:
        os.system('clear')  
        
        banner = """[bold red]
███╗   ██╗███████╗██╗  ██╗██╗   ██╗███████╗
████╗  ██║██╔════╝╚██╗██╔╝██║   ██║██╔════╝
██╔██╗ ██║█████╗   ╚███╔╝ ██║   ██║███████╗
██║╚██╗██║██╔══╝   ██╔██╗ ██║   ██║╚════██║
██║ ╚████║███████╗██╔╝ ██╗╚██████╔╝███████║
╚═╝  ╚═══╝╚══════╝╚═╝  ╚═╝ ╚═════╝ ╚══════╝
[/bold red][bold white]      C Y B E R   S E C U R I T Y   F R A M E W O R K[/bold white]
"""
        console.print(banner, justify="center")
        
        menu = """
[bold red][[/bold red][bold white]01[/bold white][bold red]][/bold red] [white]Lancer un Scan TCP[/white]        [bold red][[/bold red][bold white]04[/bold white][bold red]][/bold red] [white]Audit du Système Local[/white]
[bold red][[/bold red][bold white]02[/bold white][bold red]][/bold red] [white]Générer un Rapport HTML[/white]   [bold red][[/bold red][bold white]05[/bold white][bold red]][/bold red] [white]Dashboard (Dernier scan)[/white]
[bold red][[/bold red][bold white]03[/bold white][bold red]][/bold red] [white]Cartographie Réseau[/white]       [bold red][[/bold red][bold white]99[/bold white][bold red]][/bold red] [white]Quitter NEXUS[/white]
"""
        console.print(Panel(menu, border_style="red"))
        
        try:
            choice = console.input("\n[bold red]root@nexus[/bold red][bold white]:~#[/bold white] ").strip()
            
            if choice in ("99", "q", "exit", "quit"):
                console.print("[bold red]Déconnexion...[/bold red]")
                break
                
            elif choice == "01" or choice == "1":
                console.print("\n[bold red][!][/bold red] [white]Configuration du Scan[/white]")
                target = console.input(" ├── [?] Cible (ex: 127.0.0.1) : ").strip()
                if not target: continue
                ports = console.input(" └── [?] Ports (ex: 22,80,443) : ").strip() or "22,80,443"
                
                # NOUVEAU : On demande à l'utilisateur s'il veut forcer le mode autorisé
                auth_input = console.input(" └── [?] Mode offensif autorisé ? (o/N) : ").strip().lower()
                mode_choisi = "authorized" if auth_input == "o" else "safe"
                
                args = argparse.Namespace(
                    targets=[target], targets_option=None, ports=ports,
                    offline=False, mode=mode_choisi, timeout=0.6, concurrency=128, lab=False
                )
                console.print()
                try:
                    _run_scan(args, store)
                except Exception as e:
                    console.print(f"[bold red]Erreur:[/bold red] {e}")
                console.input("\n[bold black]Appuyez sur Entrée pour continuer...[/bold black]")
                
            elif choice == "02" or choice == "2":
                console.print("\n[bold red][!][/bold red] [white]Génération du Rapport HTML[/white]")
                scan_id = console.input(" └── [?] ID du scan (Entrée pour utiliser 'latest') : ").strip() or "latest"
                args = argparse.Namespace(scan_id=scan_id, format="html", output=Path("rapport_nexus.html"))
                console.print()
                try:
                    _run_report(args, store)
                    console.print("[bold green][+][/bold green] Rapport généré dans [bold white]rapport_nexus.html[/bold white]")
                    os.system("xdg-open rapport_nexus.html 2>/dev/null") 
                except Exception as e:
                    console.print(f"[bold red]Erreur:[/bold red] {e}")
                console.input("\n[bold black]Appuyez sur Entrée pour continuer...[/bold black]")
                
            elif choice == "03" or choice == "3":
                console.print("\n[bold red][!][/bold red] [white]Cartographie Réseau[/white]")
                scan_id = console.input(" └── [?] ID du scan (Entrée pour utiliser 'latest') : ").strip() or "latest"
                args = argparse.Namespace(scan_id=scan_id, format="dot", output=Path("graphe.dot"))
                console.print()
                try:
                    _run_map(args, store)
                    console.print("[bold green][+][/bold green] Cartographie générée dans [bold white]graphe.dot[/bold white]")
                except Exception as e:
                    console.print(f"[bold red]Erreur:[/bold red] {e}")
                console.input("\n[bold black]Appuyez sur Entrée pour continuer...[/bold black]")
                
            elif choice == "04" or choice == "4":
                console.print()
                _run_local_audit("table")
                console.input("\n[bold black]Appuyez sur Entrée pour continuer...[/bold black]")
                
            elif choice == "05" or choice == "5":
                console.print()
                _dashboard(store)
                console.input("\n[bold black]Appuyez sur Entrée pour continuer...[/bold black]")
                
        except KeyboardInterrupt:
            break

def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        store = Store(args.db)
        if args.command is None:
            _interactive_menu(store)
        elif args.command == "scan":
            _run_scan(args, store)
        elif args.command == "map":
            _run_map(args, store)
        elif args.command == "report":
            _run_report(args, store)
        elif args.command == "audit":
            _run_local_audit(args.format)
        return 0
    except KeyboardInterrupt:
        console.print("[yellow]Interruption demandée.[/yellow]")
        return 130
    except (ScopeError, PermissionError, ValueError, OSError, sqlite3.Error) as exc:
        console.print(f"[bold red]NEXUS:[/bold red] {exc}")
        return 2

if __name__ == "__main__":
    main()
