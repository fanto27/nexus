"""
NEXUS ActionGate - Moteur central d'autorisation.
Toutes les actions sensibles doivent passer par ce composant.
"""
from dataclasses import dataclass
from datetime import datetime, timezone
from rich.console import Console

console = Console()

@dataclass
class ActionRequest:
    module: str        # Ex: "tcp_scanner"
    capability: str    # Ex: "network.connect", "filesystem.read"
    target: str        # Ex: "127.0.0.1"
    mode: str          # Ex: "safe" ou "authorized"

class ActionGate:
    def __init__(self):
        # Capacités intrusives strictement interdites si l'utilisateur n'a pas mis le mode 'authorized'
        self.dangerous_capabilities = [
            "network.connect", 
            "network.exploit",
            "filesystem.write", 
            "process.inspect"
        ]

    def check(self, request: ActionRequest) -> bool:
        """Vérifie si une action est autorisée selon le mode et la cible."""
        
        # 1. Règle de base : Mode Safe = Pas d'actions intrusives
        if request.mode == "safe" and request.capability in self.dangerous_capabilities:
            self._log(request, False, f"Capacité '{request.capability}' interdite en mode SAFE.")
            return False
        
        # 2. Règle d'isolation : Bloquer les adresses système critiques par sécurité
        forbidden_targets = ["0.0.0.0", "255.255.255.255", "localhost"]
        if request.target in forbidden_targets and request.capability != "network.observe":
            self._log(request, False, "Cible système critique interdite par sécurité.")
            return False

        # 3. Si on est en mode 'authorized' ou que l'action est inoffensive
        self._log(request, True, "Action autorisée par la politique.")
        return True

    def _log(self, req: ActionRequest, decision: bool, reason: str):
        """Journalise la décision pour respecter la règle 'Evidence-first' du prompt"""
        status = "[bold green]ALLOW[/bold green]" if decision else "[bold red]DENY[/bold red]"
        time_now = datetime.now(timezone.utc).strftime("%H:%M:%S")
        
        # Affiche la décision discrètement dans la console pour l'audit
        console.print(f"[dim][{time_now}] ActionGate {status} : {req.module} demande '{req.capability}' sur {req.target} -> {reason}[/dim]")

# Instance globale prête à être importée partout dans NEXUS
gate = ActionGate()
