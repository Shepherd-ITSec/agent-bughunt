# Agend Bughunt Workshop Kit

This repository bundles everything needed for the Agend bughunting workshop: repeatable playgrounds, curated write-ups, and Model Context Protocol (MCP) helpers that let Cursor (or any MCP-aware IDE) drive security tooling hands-free. Bring it to a live session, have participants clone it, and they will land in a ready-to-explore environment that alternates between CTF-style labs, WordPress research targets, and automation scripts.

## Repository Layout

- `CTF-Agend-Playground/` — self-contained capture-the-flag style exercises (race-condition lab, survey challenge, forensics artifacts, helper scripts, etc.). Use these for fast-paced demos or individual drills.
- `WP-Agend-Playground/` — WordPress assessment workspace with analyses, PoCs, and formal reports. The included `README.md` explains the required naming conventions and methodology so attendees can follow the same structure.
- `MCPs/` — standalone MCP servers that plug into Cursor. Each folder is an installable Python package (managed with `uv`) that exposes a specialized tool:
  - `CheckFlagMCP` verifies submitted flags over HTTP.
  - `IShellMCP` provides interactive shell access with guardrails.
  - `MetasploitMCP` bridges Cursor to Metasploit RPC (list exploits, run modules, manage sessions, generate payloads).
  - `WordpressMCP` automates plugin downloads, activation, scanning, and reporting inside a standardized WordPress bench.

> **Why the `.gitignore` matters**  
> The root `.gitignore` excludes every `*-Playground/` directory except their nested `rules/` folders:
> ```
> *-Playground/
> !*-Playground/**/rules/
> ```
> This keeps bulky challenge artifacts out of version control while still allowing you to distribute any governing rules or instructions. Feel free to drop local challenge files inside the playground folders—the repo will treat them as scratch space.

## Getting Started

1. **Clone**
   ```bash
   git clone https://github.com/<org>/agend-bughunt.git
   cd agend-bughunt
   ```
2. **Python toolchain**  
   - Install [uv](https://docs.astral.sh/uv/getting-started/installation/) (recommended) or ensure Python ≥3.10 is available.  
   - For a specific MCP, run `uv sync` (or `pip install -r requirements.txt`) inside that MCP’s folder.
3. **Metasploit (optional)**  
   - Required if you plan to demonstrate `MetasploitMCP`. Start `msfrpcd` before launching the MCP so Cursor can attach.

## Installing Cursor (needed for MCP tooling)

1. Visit [https://cursor.sh/download](https://cursor.sh/download) and pick your platform.
2. **Linux (AppImage example)**  
   ```bash
   wget https://downloader.cursor.sh/linux/appImage -O Cursor.AppImage
   chmod +x Cursor.AppImage
   ./Cursor.AppImage
   ```
   Windows and macOS users can run the signed installer from the downloads page.
3. Sign in (GitHub, Google, or email) and let Cursor index this repository.
4. Open `Settings → MCP Servers` in Cursor and register any of the servers from the `MCPs/` directory. Example command for Metasploit:
   ```json
   {
     "command": "uv",
     "args": ["--directory", "/path/to/agend-bughunt/MCPs/MetasploitMCP", "run", "MetasploitMCP.py", "--transport", "stdio"],
     "env": { "MSF_PASSWORD": "supersecret" }
   }
   ```
5. Start chatting with Cursor and invoke the new tools (e.g., `metasploit.list_exploits`, `wordpress.scan_plugin`, `checkflag.verify`).

## Suggested Workshop Flow

- **Kickoff (10 min)** — Walk through this README, show the playgrounds, and explain the `.gitignore`-backed scratch areas attendees can personalize.
- **Environment prep (15 min)** — Attendees install Cursor, register at least one MCP, and skim the `WP-Agend-Playground/README.md` methodology.
- **Guided lab (30–45 min)** — Pair Cursor with `MetasploitMCP` or `WordpressMCP` to demonstrate automated recon, exploitation, and reporting.
- **Independent exploration** — Participants pick either CTF or WordPress tracks, capture findings, and (optionally) submit through `CheckFlagMCP`.
- **Wrap-up** — Collect reports/flags from `rules/` folders so nothing sensitive ends up in git history.

## Tips for Facilitators

- Keep heavy VM images, pcap files, and wordlists inside the playground folders; git will happily ignore them.
- Encourage responsible disclosure: every WordPress analysis directory already includes guidance on reporting and severity triage.
- Mix and match MCP servers—Cursor can call them concurrently, which makes demonstrations smoother than juggling CLI windows.
- Document new rules or scoring guidance inside `rules/` subdirectories so they *are* tracked.

## License & Responsible Use

This repository is for educational, authorized security testing. Only run the included tooling in lab environments or against systems where you have explicit permission. When in doubt, err on the side of caution and keep sensitive evidence within the ignored playground directories.