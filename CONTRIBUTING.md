# Contributing

```bash
python -m venv .venv && .venv/bin/pip install -e ".[dev]"
```

```bash
.venv/bin/pytest && .venv/bin/ruff check . && .venv/bin/mypy
```

Guidelines:

- **Security changes need tests.** A new check needs a test proving it blocks. A relaxed check needs a test proving the attack suite still passes under the `overbroad` compiler.
- **Never fail open.** Any exception path in `pre_tool_call` must end in `block`. Any compiler failure must end in the fallback policy.
- **The evaluator stays deterministic.** No network or LLM calls on the per-tool-call path.
- **Tool mappings.** Adding a mapping for a popular tool or MCP server to `agentsfence/policies/defaults.yaml` is the easiest high-value contribution. Include `recipient_args`, `domain_args` and `path_args` where they apply.
- **Hermes API changes.** If Hermes changes a hook contract, update `HERMES_API.md` first, then the code. Feature-detect APIs that older supported Hermes releases lack, and run `tests/test_hermes_integration.py` against the oldest supported release (`AGENTSFENCE_HERMES_PYTHON`, pointing at a throwaway install, never your own `~/.hermes`); CI runs the matrix in `.github/workflows/ci.yml`, including a pinned Hermes `main` revision (Python 3.14) and a non-blocking job on the tip of `main`.

Report vulnerabilities privately. See [SECURITY.md](SECURITY.md).
