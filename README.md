# Bob App Store — aplikacje dla umbrelOS

Community App Store z aplikacjami autorstwa Boba. Dodaj URL:
`https://github.com/agentaibob/bob-app-store`

![Netmon](https://img.shields.io/badge/netmon-1.0.34-green) ![Garmin](https://img.shields.io/badge/garmin-1.0.4-green) ![Hermes Monitor](https://img.shields.io/badge/hermes_monitor-1.18.0-green)

---

## 1. Network Monitor (bob-network-monitor)

A network traffic monitor for **umbrelOS** that shows real-time traffic of your whole system — both as a live widget on the UmbrelOS home screen and as a full web dashboard.

### Features

- **Home screen widget** (four-stats): download speed, upload speed, total received, total sent
- **Web dashboard** (Vault-Tec / Pip-Boy style): 4 stat cards, per-app table (app name, remote IPs with ports, reverse-DNS names, live speeds, totals), "Pozostałe" row for unassigned traffic
- Dynamic units B/s → kB/s → MB/s (and totals to GB)

### How it works

- A collector container runs with `network_mode: host` + `pid: host`, so it can see the host's network interfaces and every container's network namespace.
- Each container's virtual interface (veth) is mapped to its app via `iflink ↔ ifindex` pairing, with a byte-counter fallback (host veth RX = container TX).
- Per-second byte counters give accurate live speeds; Docker API calls (which are expensive) are cached and refreshed every 12 seconds.
- The widget and the web dashboard share a single source of truth, so the numbers always match.

### Web dashboard endpoints

- `/` — web dashboard (cards + per-app table, Pip-Boy CRT theme)
- `/api/totals` — total rates & totals (shared source with the widget)
- `/api/stats` — per-app rows + system row
- `/api/diag` — diagnostics (docker status, veth mapping)
- `/widgets/network` — four-stats JSON for the home screen widget

---

## 2. Garmin Monitor (bob-garmin-monitor)

Dashboard + home-screen widget for **Garmin Connect** data: daily rides, distance, speed, heart rate, stress, sleep, HRV.

- Port: 8125
- In-app Garmin login form; tokens stored in `${APP_DATA_DIR}/data/.garminconnect`
- Shows the **previous day's** data (consistent with the morning bike report)

---

## 3. Hermes Monitor (bob-hermes-monitor)

Dashboard + home-screen widget for **Hermes Agent**: live gateway & profile status,
token usage and cost, cron jobs and vigilance/health signals.

- Port: 8126
- Reads Hermes data **read-only** (host path
  `/home/umbrel/umbrel/app-data/hermes-agent/data/hermes` → `/hermes-data`)
- Widget (three-stats): profile online, tokens total, cost total (est.)
- Dashboard: KPI, wykorzystanie tokenów/kosztów, top modele (tabela), ostatnie sesje,
  pełny status gateway per-profil (kropka stanu, pid, uptime, błędy, cron, platformy),
  system
- Endpoints: `/` (dashboard), `/api/health`, `/api/status`, `/api/sessions`,
  `/api/usage`, `/api/cron/jobs`, `/api/alerts`,
  `/api/metrics/{name}`, `/widgets/hermes`

---

## Updating

New versions are published as a fresh single commit in this repository. In umbrelOS:
**App Store → Community → remove the "Bob" store → add the URL again** → update the app.

> umbrelOS caches community app stores; removing and re-adding the store URL is required to pick up new versions.

## Why the store shows no README description

The UmbrelOS Community App Store does **not** read this README. It shows each app's
`tagline` and `description` fields from the app manifest
(`bob-network-monitor/umbrel-app.yml`, `bob-garmin-monitor/umbrel-app.yml`). The README only
documents the project on GitHub.

## License

MIT — free to use, modify and share.
