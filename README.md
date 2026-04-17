# AssistantAudit-Agent

Agent léger pour audits de sécurité IT — se connecte au serveur [AssistantAudit](https://github.com/T0SAGA97/AssistantAudit) via mTLS + WebSocket, reçoit les tâches d'audit et exécute les outils de collecte.

## Fonctionnalités

- **Connexion temps réel** — WebSocket persistant avec reconnexion automatique (backoff exponentiel)
- **Outils d'audit intégrés** — nmap, ORADAD, collecteurs Active Directory
- **mTLS** — Authentification mutuelle par certificats clients pour toutes les communications
- **File d'attente hors ligne** — Les résultats sont mis en queue localement si le serveur est injoignable, puis envoyés automatiquement à la reconnexion
- **Chiffrement DPAPI** — Le JWT est chiffré via DPAPI sur Windows (fallback base64 sur les autres plateformes)
- **Heartbeat** — Signal de vie envoyé au serveur toutes les 30 secondes

## Prérequis

- Python 3.11+
- Windows 10/11 (plateforme cible)
- [nmap](https://nmap.org/) installé et accessible dans le `PATH`
- [ORADAD](https://github.com/ANSSI-FR/ORADAD) (si utilisé)
- Accès réseau vers le serveur AssistantAudit

## Installation

```bash
# Cloner le dépôt
git clone https://github.com/T0SAGA97/AssistantAudit-Agent.git
cd AssistantAudit-Agent

# Créer un environnement virtuel
python -m venv .venv
.venv\Scripts\activate  # Windows

# Installer le package
pip install -e .

# (Optionnel) Dépendances de développement
pip install -e ".[dev]"
```

## Utilisation

### 1. Enrôlement

L'agent doit d'abord être enregistré auprès du serveur. Le code d'enrollment est fourni par l'administrateur via l'interface AssistantAudit.

```powershell
assistant-audit-agent enroll --server https://serveur:8000 --code ABCD1234
```

Options disponibles :

| Option       | Description                                    | Requis |
|-------------|------------------------------------------------|--------|
| `--server`  | URL du serveur AssistantAudit                  | Oui    |
| `--code`    | Code d'enrollment fourni par le serveur        | Oui    |
| `--name`    | Nom de l'agent (défaut : hostname)             | Non    |
| `--ca-cert` | Chemin vers le certificat CA du serveur        | Non    |

L'enrollment génère :
- `agent.json` — configuration locale (UUID, JWT chiffré, URL serveur)
- `certs/` — certificats mTLS (CA, certificat agent, clé privée)

### 2. Démarrage du daemon

```powershell
assistant-audit-agent start
```

L'agent se connecte au serveur, envoie des heartbeats et attend les tâches d'audit.

### 3. Vérifier l'état

```powershell
assistant-audit-agent status
```

### 4. Autres commandes

```powershell
# Afficher la version
assistant-audit-agent version

# Installer comme service Windows (à venir)
assistant-audit-agent install-service
```

## Architecture

```
main.py (CLI Click)
  ├── enrollment.py          Enrôlement initial
  └── websocket_client.py    Connexion persistante
        ├── heartbeat.py     Signal de vie (30s)
        ├── task_runner.py   Dispatch des tâches
        │     ├── nmap_tool.py
        │     ├── oradad_tool.py
        │     └── ad_collector_tool.py
        └── uploader.py      Upload des résultats (HTTPS + mTLS)
```

L'agent fonctionne sur une **boucle asyncio unique**. Les outils d'audit sont exécutés comme **sous-processus** — l'agent n'importe jamais le code des outils directement.

## Structure du projet

```
AssistantAudit-Agent/
├── src/assistant_audit_agent/
│   ├── main.py              Point d'entrée CLI
│   ├── config.py            Chargement agent.json + chiffrement DPAPI
│   ├── enrollment.py        Flux d'enrôlement
│   ├── websocket_client.py  Client WebSocket + reconnexion
│   ├── heartbeat.py         Heartbeat périodique
│   ├── task_runner.py       Dispatcher de tâches
│   ├── tools/               Un module par outil d'audit
│   ├── uploader.py          Upload résultats + file offline
│   └── logging_config.py    Logging structuré
├── certs/                   Certificats mTLS (généré à l'enrollment)
├── queue/                   File d'attente hors ligne
├── tests/
├── agent.json               Config locale (généré à l'enrollment)
└── pyproject.toml
```

## Tests

```bash
pytest -q
```

## Sécurité

- Toutes les communications utilisent **mTLS** (certificats clients)
- Le JWT est **chiffré avec DPAPI** sur Windows
- Seuls les outils **whitelistés** peuvent être exécutés (nmap, oradad, ad_collector)
- Aucune commande arbitraire n'est acceptée — le serveur dispatche, l'agent exécute uniquement les outils autorisés
- Les sous-processus sont lancés **sans `shell=True`**
- Les credentials et tokens ne sont **jamais journalisés**

## Licence

[AGPL-3.0](LICENSE)
