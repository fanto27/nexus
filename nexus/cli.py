from __future__ import annotations

import argparse
import asyncio
import ipaddress
import json
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


console = Console()


def _add_child_mode_flags(parser: argparse.ArgumentParser) -> None:
    group = parser.add_mutually_exclusive_group()
    group.add_argument(
        "--safe",
        dest="mode",
        action="store_const",
        const="safe",
        default=argparse.SUPPRESS,
        help="Interdire les actions intrusives (mode par défaut).",
    )
    group.add_argument(
        "--authorized",
        dest="mode",
        action="store_const",
        const="authorized",
        default=argparse.SUPPRESS,
        help="Déclarer une autorisation explicite pour la portée demandée.",
    )
    parser.add_argument(
        "--lab",
        action="store_true",
        default=argparse.SUPPRESS,
        help="Restreindre la portée aux adresses locales/privées/link-local.",
    )
    parser.add_argument(
        "--offline",
        action="store_true",
        default=argparse.SUPPRESS,
        help="Interdire la résolution DNS ; les sondes vers les cibles restent nécessaires.",
    )
    parser.add_argument(
        "--db",
        type=Path,
        default=argparse.SUPPRESS,
        help="Chemin de la base SQLite locale.",
    )


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="nexus",
        description="NEXUS — framework local d'audit et de sécurité",
    )
    parser.add_argument("--version", action="version", version=f"NEXUS {__version__}")

    root_mode = parser.add_mutually_exclusive_group()
    root_mode.add_argument(
        "--safe",
        dest="mode",
        action="store_const",
        const="safe",
        help="Mode sûr, activé par défaut.",
    )
    root_mode.add_argument(
        "--authorized",
        dest="mode",
        action="store_const",
        const="authorized",
        help="Activer le mode autorisé, avec confirmation interactive.",
    )
    parser.set_defaults(mode="safe", lab=False, offline=False, db=None)

    parser.add_argument("--lab", action="store_true", help="Limiter aux plages de lab.")
    parser.add_argument(
        "--offline",
        action="store_true",
        help="Pas de DNS ni d'enrichissement distant.",
    )
    parser.add_argument("--db", type=Path, help="Chemin SQLite.")

    commands = parser.add_subparsers(dest="command")

    scan = commands.add_parser("scan", help="Scan TCP à faible impact.")
    _add_child_mode_flags(scan)
    scan.add_argument("targets", nargs="*", help="IP, CIDR ou nom d'hôte.")
    scan.add_argument(
        "-t",
        "--target",
        dest="targets_option",
        nargs="+",
        help="Cible(s), forme optionnelle de l'argument positionnel.",
    )
    scan.add_argument("--ports", default=DEFAULT_PORTS_CSV)
    scan.add_argument("--timeout", type=float, default=0.6)
    scan.add_argument("--concurrency", type=int, default=128)

    map_parser = commands.add_parser("map", help="Exporter le graphe d'un scan enregistré.")
    map_parser.add_argument("--scan-id", default="latest")
    map_parser.add_argument("--format", choices=("json", "dot"), default="json")
    map_parser.add_argument("--output", type=Path)

    report = commands.add_parser("report", help="Produire un rapport.")
    report.add_argument("--scan-id", default="latest")
    report.add_argument(
        "--format",
        choices=("json", "markdown", "html"),
        default="markdown",
    )
    report.add_argument("--output", type=Path)

    audit = commands.add_parser("audit", help="Audit local.")
    audit_commands = audit.add_subparsers(dest="audit_command", required=True)
    local = audit_commands.add_parser("local", help="Résumé local en lecture seule.")
    local.add_argument("--format", choices=("table", "json"), default="table")

    plugins = commands.add_parser("plugins", help="Lister les plugins connus.")
    plugin_commands = plugins.add_subparsers(dest="plugin_command")
    plugin_info = plugin_commands.add_parser("info", help="Détails d'un plugin.")
    plugin_info.add_argument("name")

    return parser


def _load_scan(store: Store, scan_id: str) -> ScanResult:
    selected_id = store.latest_scan_id() if scan_id == "latest" else scan_id
    if selected_id is None:
        raise ValueError("Aucun scan enregistré")
    result = store.load_scan(selected_id)
    if result is None:
        raise ValueError(f"Scan inconnu : {selected_id}")
    return result


def _dashboard(store: Store) -> None:
    title = Text()
    title.append("N E X U S\n", style="bold cyan")
    title.append("CYBER SECURITY FRAMEWORK", style="white")
    console.print(Panel(title, border_style="cyan", expand=False))

    scan_id = store.latest_scan_id()
    if scan_id is None:
        console.print(
            Panel(
                "STATUS     IDLE\nTARGET     —\nHOSTS      0\n"
                "SERVICES   0\nFINDINGS   0",
                title="Dashboard",
                border_style="blue",
            )
        )
        console.print("Commence avec [bold]nexus scan --target 127.0.0.1[/bold]")
        return

    result = _load_scan(store, scan_id)
    score = exposure_index(result.services)
    responsive = len({service.address for service in result.services})

    console.print(
        Panel(
            f"SCAN ID    {result.scan_id}\n"
            f"STATUS     {result.status.upper()}\n"
            f"TARGETS    {len(result.targets)}\n"
            f"RESPONSES  {responsive}\n"
            f"SERVICES   {len(result.services)}\n"
            f"FINDINGS   {len(result.findings)}\n"
            f"EXPOSURE   {score.score}/100 (heuristique)",
            title="Dernier scan",
            border_style="cyan",
        )
    )


def _render_scan(result: ScanResult) -> None:
    score = exposure_index(result.services)
    responsive = len({service.address for service in result.services})

    console.print(
        Panel(
            f"ID         {result.scan_id}\n"
            f"TARGETS    {len(result.targets)}\n"
            f"RESPONSES  {responsive}\n"
            f"SERVICES   {len(result.services)}\n"
            f"FINDINGS   {len(result.findings)}\n"
            f"EXPOSURE   {score.score}/100",
            title="NEXUS — Scan terminé",
            border_style="green",
        )
    )

    table = Table(title="Services TCP observés")
    table.add_column("Adresse", style="cyan")
    table.add_column("Port", justify="right")
    table.add_column("Protocole")
    table.add_column("Service")
    table.add_column("Version")

    for service in result.services:
        table.add_row(
            service.address,
            str(service.port),
            service.protocol,
            service.name,
            service.version or "non déterminée",
        )

    if result.services:
        console.print(table)
    else:
        console.print(
            "Aucun port ouvert observé parmi les ports testés. "
            "Cela ne prouve pas que l'hôte est inaccessible."
        )


def _confirm_scan(
    targets: list[str],
    ports: list[int],
    *,
    mode: str,
) -> None:
    if not sys.stdin.isatty():
        raise PermissionError(
            "Le consentement interactif est obligatoire ; "
            "aucun contournement non interactif n'est fourni."
        )

    preview = ", ".join(targets[:8])
    if len(targets) > 8:
        preview += f", … (+{len(targets) - 8})"

    body = Text()
    body.append(f"Cibles : {preview}\n")
    body.append(f"Ports   : {len(ports)}\n")
    body.append(f"Sondes  : {len(targets) * len(ports)}\n")
    body.append(
        "Sonde   : connexion TCP simple ; aucune bannière ni exploitation"
    )
    console.print(Panel(body, title="Portée demandée", border_style="yellow"))

    if mode == "authorized":
        answer = console.input(
            "Attestez-vous disposer d'une autorisation explicite ? "
            'Tapez "I AM AUTHORIZED" : '
        )
        if answer.strip() != "I AM AUTHORIZED":
            raise PermissionError("Attestation refusée")

    expected = f"SCAN {len(targets)}"
    answer = console.input(f'Tapez exactement "{expected}" pour lancer : ')
    if answer.strip() != expected:
        raise PermissionError("Scan annulé")


def _write_private(path: Path, content: str) -> None:
    path = path.expanduser()
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8")
    try:
        path.chmod(0o600)
    except OSError:
        pass


def _run_scan(args: argparse.Namespace, store: Store) -> None:
    raw_targets = list(args.targets)
    if args.targets_option:
        raw_targets.extend(args.targets_option)
    if not raw_targets:
        raise ScopeError("Indiquer une cible avec --target ou un argument positionnel")

    addresses = expand_targets(raw_targets, offline=args.offline, max_hosts=256)
    ports = parse_ports(args.ports)
    probe_count = len(addresses) * len(ports)

    if args.mode == "safe":
        if not is_local_scope(addresses):
            raise PermissionError(
                "En mode --safe, les cibles doivent être privées, loopback "
                "ou link-local. Une portée publique exige --authorized."
            )
        if len(ports) > 2048 or probe_count > 65_536:
            raise ScopeError(
                "Limite --safe dépassée : maximum 2048 ports et 65536 sondes."
            )
        max_concurrency = 256
    else:
        if probe_count > 1_000_000:
            raise ScopeError("Limite du mode autorisé : 1 000 000 sondes.")
        max_concurrency = 512

    if args.lab and not is_local_scope(addresses):
        raise PermissionError("--lab refuse les adresses hors des plages locales")

    if args.concurrency > max_concurrency:
        raise ScopeError(
            f"Concurrence maximale dans ce mode : {max_concurrency}"
        )

    _confirm_scan(addresses, ports, mode=args.mode)

    started = datetime.now(timezone.utc).isoformat()
    timer = monotonic()

    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        BarColumn(),
        TaskProgressColumn(),
        console=console,
    ) as progress:
        task = progress.add_task("Sondes TCP", total=probe_count)

        def update(done: int, _total: int) -> None:
            progress.update(task, completed=done)

        services = asyncio.run(
            scan_tcp(
                addresses,
                ports,
                timeout=args.timeout,
                concurrency=args.concurrency,
                progress=update,
            )
        )

    result = ScanResult(
        targets=addresses,
        ports=ports,
        services=services,
        started_at=started,
        duration_seconds=monotonic() - timer,
    )
    store.save_scan(result, mode=args.mode)
    _render_scan(result)


def _run_map(args: argparse.Namespace, store: Store) -> None:
    result = _load_scan(store, args.scan_id)
    content = to_json(result) if args.format == "json" else to_dot(result)

    if args.output:
        _write_private(args.output, content)
        console.print(f"Graphe écrit dans {args.output}")
    else:
        sys.stdout.write(content)


def _run_report(args: argparse.Namespace, store: Store) -> None:
    result = _load_scan(store, args.scan_id)
    actions = store.list_actions(result.scan_id)
    content = render_report(result, fmt=args.format, actions=actions)

    if args.output:
        _write_private(args.output, content)
        console.print(f"Rapport écrit dans {args.output}")
    else:
        sys.stdout.write(content)


def _run_local_audit(fmt: str) -> None:
    snapshot = local_snapshot()

    if fmt == "json":
        sys.stdout.write(json.dumps(snapshot, indent=2, ensure_ascii=False) + "\n")
        return

    table = Table(title="Audit local — lecture seule")
    table.add_column("Champ", style="cyan")
    table.add_column("Valeur")
    for key in (
        "platform",
        "architecture",
        "cpu_count",
        "memory_total_mb",
        "effective_uid",
        "running_as_root",
        "interfaces",
        "collection_mode",
    ):
        table.add_row(key, str(snapshot[key]))
    console.print(table)

    tools = Table(title="Outils détectés")
    tools.add_column("Outil", style="cyan")
    tools.add_column("Disponible")
    for name, present in snapshot["tools"].items():
        tools.add_row(name, "oui" if present else "non")
    console.print(tools)


def _run_plugins(name: str | None) -> None:
    if name is None:
        table = Table(title="Catalogue NEXUS")
        table.add_column("Nom", style="cyan")
        table.add_column("Catégorie")
        table.add_column("Risque")
        table.add_column("Description")
        for plugin in BUILTIN_CATALOG:
            table.add_row(
                plugin.name,
                plugin.category,
                plugin.risk_level,
                plugin.description,
            )
        console.print(table)
        console.print(
            "La liste n'importe ni n'exécute aucun plugin externe."
        )
        return

    plugin = next((item for item in BUILTIN_CATALOG if item.name == name), None)
    if plugin is None:
        raise ValueError(f"Plugin inconnu : {name}")

    console.print(
        Panel(
            f"Nom          {plugin.name}\n"
            f"Version      {plugin.version}\n"
            f"Auteur       {plugin.author}\n"
            f"Catégorie    {plugin.category}\n"
            f"Risque       {plugin.risk_level}\n"
            f"Permissions  {', '.join(plugin.required_permissions)}\n"
            f"Cibles       {', '.join(plugin.targets)}\n"
            f"Capacités    {', '.join(plugin.capabilities)}\n\n"
            f"{plugin.description}",
            title="Plugin",
            border_style="magenta",
        )
    )


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    try:
        store = Store(args.db)

        if args.command is None:
            _dashboard(store)
        elif args.command == "scan":
            _run_scan(args, store)
        elif args.command == "map":
            _run_map(args, store)
        elif args.command == "report":
            _run_report(args, store)
        elif args.command == "audit":
            _run_local_audit(args.format)
        elif args.command == "plugins":
            selected = (
                args.name
                if getattr(args, "plugin_command", None) == "info"
                else None
            )
            _run_plugins(selected)
        else:
            parser.print_help()

        return 0
    except KeyboardInterrupt:
        console.print("[yellow]Interruption demandée.[/yellow]")
        return 130
    except (ScopeError, PermissionError, ValueError, OSError, sqlite3.Error) as exc:
        console.print(f"[bold red]NEXUS:[/bold red] {exc}")
        return 2
