📁 Enterprise Password Vault with Auto‑Rotation

Description
A self‑contained password vault with encrypted storage (Fernet). Provides a REST API to add, retrieve, list, and delete secrets. Automatically rotates secrets on a configurable schedule (default 30 days). Includes a web dashboard.

Navigate to the project folder.

Create a virtual environment (recommended):
bash

python3 -m venv venv
source venv/bin/activate   # On Windows: venv\Scripts\activate

    Install dependencies – each project has its own requirements.txt or lists the required packages.

    Run the main script as described in the project’s section.

    Note: Some projects require system tools (e.g., nmap, subfinder, httpx, zeek). Installation instructions are provided per project.
    

Core Technologies

    Flask, cryptography, pyyaml

Features

    Encrypted JSON storage

    REST API (CRUD + rotation)

    Auto‑rotation background thread

    Access logging

    Dashboard for monitoring

Installation & Setup
bash

pip install flask pyyaml cryptography

Usage

    Run python vault_server.py (listens on port 5003)

    Dashboard at http://127.0.0.1:5003

API Endpoints

    GET /api/secrets – list names

    GET /api/secrets/<name> – get metadata

    GET /api/secrets/<name>/value – get secret value

    POST /api/secrets – add secret (JSON: {"name":"x","value":"y"})

    POST /api/secrets/<name>/rotate – rotate

    DELETE /api/secrets/<name> – delete

    POST /api/rotate_all – rotate all
