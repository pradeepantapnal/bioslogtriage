# bioslogtriage

`bioslogtriage` is a lightweight Python toolkit for experimenting with BIOS log triage workflows.

At the moment, the project includes:

- A minimal command-line interface (CLI).
- A local LLM integration via [Ollama](https://ollama.com/) for structured JSON responses.
- Basic scaffolding modules for ingestion, normalization, and rules evaluation.

---

## Features

- **Local-first LLM support** via Ollama (`/api/generate`).
- **JSON-oriented generation** for machine-readable triage outputs.
- **Configurable model + host** from the CLI.
- **Simple project scaffold** you can extend with:
  - `triage.ingest`
  - `triage.normalize`
  - `triage.rules.loader`
  - `triage.rules.engine`

---

## Requirements

- **Python**: 3.10+
- **pip**: latest recommended
- **Ollama** (optional, only required when running with `--llm`)

Python dependency declared by the project:

- `requests>=2.31`

---

## Installation

### 1) Clone the repository

```bash
git clone <your-repo-url>
cd bioslogtriage
```

### 2) Create and activate a virtual environment

#### macOS/Linux

```bash
python3 -m venv .venv
source .venv/bin/activate
```

#### Windows (PowerShell)

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
```

### 3) Install the project

Install in editable mode for development:

```bash
pip install -e .
```

---

## Ollama Setup (Optional, for LLM mode)

If you want to use the local LLM flow (`--llm`):

1. Install and start Ollama.
2. Pull the default model used by this project:

```bash
ollama pull qwen2.5:7b
```

3. Ensure Ollama is reachable at:

```text
http://localhost:11434
```

You can override both host and model in CLI arguments.

---

## Usage

> The project currently exposes behavior through the Python module entrypoint.

### Basic CLI invocation

```bash
python -m triage.cli
```

Expected output:

```text
bioslogtriage CLI
```

### Run with local LLM enabled

```bash
python -m triage.cli --llm
```

What this does:

- Connects to Ollama.
- Sends a sample BIOS triage prompt.
- Requests JSON output.
- Prints formatted JSON to stdout.

### Override Ollama host and model

```bash
python -m triage.cli --llm \
  --ollama-host http://localhost:11434 \
  --model qwen2.5:7b
```

---

## Project Layout

```text
bioslogtriage/
├── fixtures/
│   └── synthetic_logs/
├── src/
│   └── triage/
│       ├── cli.py
│       ├── config.py
│       ├── ingest.py
│       ├── normalize.py
│       ├── llm/
│       │   └── ollama_client.py
│       ├── rules/
│       │   ├── engine.py
│       │   └── loader.py
│       └── schemas/
│           └── triage.schema.json
└── tests/
```

---

## Development

### Run tests

```bash
pytest
```

### Notes for contributors

- `triage.llm.ollama_client.OllamaClient` is intentionally small and easy to mock in tests.
- The `schema` parameter is currently accepted by `generate_json(...)` for forward compatibility.
- Ingestion/normalization/rules modules are scaffolded and ready for implementation.

---

## Troubleshooting

### `RuntimeError: The 'requests' package is required for OllamaClient`

Install dependencies again:

```bash
pip install -e .
```

### Connection error to Ollama

- Confirm Ollama is running.
- Verify host/port (`--ollama-host`).
- Test model availability:

```bash
ollama list
```

### HTTP errors from Ollama

- Ensure your selected model is pulled locally.
- Retry with an explicit model argument:

```bash
python -m triage.cli --llm --model qwen2.5:7b
```

---

## License

This project is licensed under the terms in `LICENSE`.
