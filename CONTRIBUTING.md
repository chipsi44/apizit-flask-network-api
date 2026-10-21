# Contributing

Use Python 3.12. Install requirements-dev.txt in a virtual environment, then run
`ruff check .`, `ruff format --check .`, `pytest -q` and
`python -c "from app import app; assert app is not None"`.

Network tests use an owned loopback HTTP server. Internet qualification is separate,
explicit, sequential and bounded. Preserve the optional token's fail-closed behavior and
all resource caps. APIZIT deployments use gateway API-key protection by default.
Update the README and regression tests whenever a route or security contract changes.
Never commit credentials, local qualification artifacts or generated runtime handlers.
