# Network diagnostic fixture guidelines

- Standalone Python 3.12 and Flask; seven explicit routes, root pinned manifests.
- No Dockerfile, customer Lambda handler, infrastructure or APIZIT-internal imports.
- All diagnostic routes require NETWORK_PROBE_TOKEN (at least 32 characters).
- Keep hard process deadlines, byte caps, redirect limits and closed validation.
- Never inspect environment credentials, fetch metadata credential paths, mutate AWS,
  send UDP payloads, scan port ranges or generate unbounded traffic.
- Non-global destinations may be connected to, but HTTP response bodies stay suppressed.
- Do not log request payloads, probe tokens, outbound credentials or exception strings.
- CI uses owned local peers and doubles; never contact third parties or real AWS.
- Run Ruff, pytest, import checks and the normal APIZIT local discovery before publication.
- Publish on codex/ branches through PR and green CI. TEST launch is explicitly requested
  in this campaign; PROD publication requires separate owner authorization.
