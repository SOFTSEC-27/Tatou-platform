# Tatou
A web platform for pdf watermarking. This project is intended for pedagogical use, and contain security vulnerabilities. Do not deploy on an open network.

## Instructions

The following instructions are meant for a bash terminal on a Linux machine. If you are using something else, you will need to adapt them.

To clone the repo, you can simply run:

```bash
git clone https://github.com/SOFTSEC-27/Tatou-platform.git
```

## Install and run tests

### Linux / Bash

From the repository root:

```bash
cd server
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -e ".[dev]"
python -m pip install "pytest==8.4.2" "hypothesis==6.142.3" "pytest-cov==7.0.0"

python -m pytest test
```

### Windows / PowerShell

From the repository root:

```powershell
cd server
python -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install -e ".[dev]"
python -m pip install "pytest==8.4.2" "hypothesis==6.142.3" "pytest-cov==7.0.0"

python -m pytest test
```

### Coverage report

From `server`, with the Python environment activated:

```bash
python -m pytest test --cov=src --cov-branch --cov-report=term-missing --cov-report=html:coverage-report
```

## Deploy with Docker Compose

### Linux / Bash

```bash
cp sample.env .env
cp flag.example flag
cp server/flag.example server/flag
```

### Windows / PowerShell

```powershell
Copy-Item sample.env .env
Copy-Item flag.example flag
Copy-Item server/flag.example server/flag
```

Edit `.env` to set the required passwords and deployment settings. Generate a
secret with the following command and set it as `SECRET_KEY` in `.env`:

```bash
python -c "import secrets; print(secrets.token_urlsafe(48))"
```

The example flag files are for local setup. Real deployment flags, credentials
and private keys must stay outside Git. RMAP operation also requires the server
keys and trusted identity keys configured for the deployment.

Build and start the containers:

```bash
docker compose up --build -d
docker compose logs -f
```

Check the API from another terminal:

```bash
# Linux / Bash
curl http://127.0.0.1:5000/healthz
```

```powershell
# Windows / PowerShell
curl.exe -i "http://127.0.0.1:5000/healthz"
```

Open <http://127.0.0.1:5000> to access the website.



