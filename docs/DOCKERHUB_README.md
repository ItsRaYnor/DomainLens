# DomainLens

Domain Intelligence Toolkit — a local web tool for fast domain analysis,
similar to MX Toolbox and internet.nl. WHOIS, DNS, DNSSEC, SPF/DMARC/DKIM,
MTA-STS/TLS-RPT, SSL/TLS certificate + NCSC TLS Guidelines 2025-05, HTTP
security headers, blacklist and port checks, a passive security audit
(subdomain takeover, exposed `.git`/`.env`, CORS, DNS/mail gaps), JS
dependency & secrets scanning, DNS monitoring with scheduling, OSINT
enrichment, and printable reports.

Source & full documentation: https://github.com/ItsRaYnor/DomainLens

## Quick start

```bash
docker run -d \
  --name domainlens \
  -p 5050:5000 \
  -v domainlens-data:/data \
  -e DOMAINLENS_SECRET_KEY=change-me-openssl-rand-hex-32 \
  itsraynor/domainlens:latest
```

Open **http://localhost:5050**, enter a domain, and click **Scan**.

## Docker Compose

```yaml
services:
  domainlens:
    image: itsraynor/domainlens:latest
    container_name: domainlens
    ports:
      - "5050:5000"
    environment:
      DOMAINLENS_SECRET_KEY: "change-me-openssl-rand-hex-32"
      DOMAINLENS_DB: /data/domainlens.db
      DOMAINLENS_HOST: 0.0.0.0
      DOMAINLENS_MONITOR_AUTORUN: "1"
    volumes:
      - domainlens-data:/data
    restart: unless-stopped

volumes:
  domainlens-data:
```

Ready-to-use Portainer/Synology stacks: see `docker-compose.portainer.yml`
and `docker-compose.dockerhub.yml` in the GitHub repo.

## Important environment variables

| Variable | Purpose |
|---|---|
| `DOMAINLENS_SECRET_KEY` | Encrypts stored integration credentials and signs session cookies. **Set this once and keep it** — changing it locks out previously stored credentials. |
| `DOMAINLENS_DB` | Path to the SQLite database (default `/data/domainlens.db`) |
| `DOMAINLENS_HOST` / `DOMAINLENS_PORT` | Bind address and port (default `0.0.0.0:5000`) |
| `DOMAINLENS_MONITOR_AUTORUN` | Background scheduler for recurring monitors, `1`/`0` |
| `AUTH_LOCAL_ENABLED` / `LOCAL_ADMIN_EMAIL` / `LOCAL_ADMIN_PASSWORD` | Local login + bootstrap admin |
| `OAUTH_ENABLED` / `OAUTH_PROVIDER` | Google/GitHub/Microsoft/OIDC sign-in |

Full variable reference, security notes, and OAuth/SAML/SCIM setup: see the
[README](https://github.com/ItsRaYnor/DomainLens#readme).

## Tags

- `latest` / `<version>` (e.g. `0.0.1`) — multi-arch: `linux/amd64`, `linux/arm64`

## Security notes

- Ships with authentication **off** by default — only expose beyond
  `127.0.0.1` after enabling `AUTH_LOCAL_ENABLED` or `OAUTH_ENABLED`.
- The **Active Vulnerability Scan** check is opt-in and off by default; only
  use it against domains you control or have explicit permission to test.

## License

MIT — see [LICENSE](https://github.com/ItsRaYnor/DomainLens/blob/main/LICENSE)
