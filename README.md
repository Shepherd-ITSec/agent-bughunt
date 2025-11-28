# Agend Bughunt Workshop Kit

This repository bundles everything needed for the Agend bughunting workshop: repeatable playgrounds, curated write-ups, and Model Context Protocol (MCP) helpers that let Cursor (or any MCP-aware IDE) drive security tooling hands-free. Bring it to a live session, have participants clone it, and they will land in a ready-to-explore environment that alternates between CTF-style labs, WordPress research targets, and automation scripts.

## Repository Layout

- `CTF-Agend-Playground/` — self-contained capture-the-flag style exercises (race-condition lab, survey challenge, forensics artifacts, helper scripts, etc.). Use these for fast-paced demos or individual drills.
- `WP-Agend-Playground/` — WordPress assessment workspace with analyses, PoCs, and formal reports. 
- `MCPs/` — standalone MCP servers. Each folder is an installable Python package (managed with `uv`) that exposes a specialized tool:
  - `CheckFlagMCP` verifies submitted flags over HTTP if given session cookie.
  - `IShellMCP` provides incremental shell access for remote explotation.
  - `MetasploitMCP` bridges Cursor to Metasploit RPC (list exploits, run modules, manage sessions, generate payloads).
  - `WordpressMCP` automates plugin downloads, activation, scanning, and reporting inside a standardized WordPress bench.


## Getting Started

1. **Clone**
   ```bash
   git clone https://github.com/Shepherd-ITSec/agend-bughunt.git
   cd agend-bughunt
   ```
2. **Python toolchain**  
   - Install [uv](https://docs.astral.sh/uv/getting-started/installation/) (recommended) or ensure Python ≥3.10 is available.  
   - For a specific MCP, run `uv sync` (or `pip install -r requirements.txt`) inside that MCP’s folder to make it aviable.
3. **Metasploit (optional)**  
   - If you like to use the `MetasploitMCP`, install methasploid and start the API server with `msfrpcd -P pass123 -a 127.0.0.1 -p 55553 -S`.
4. **Wordpress (optional)**
   - If you would like to test wordpress plugins you need to setup a wordpress enviroment
   - Install [docker](https://docs.ddev.com/en/stable/users/install/docker-installation/)
   - Install [ddev](https://docs.ddev.com/en/stable/users/install/ddev-installation/)
   - Clone the [WPScan Vulnerability Testbench](https://github.com/Automattic/wpscan-vulnerability-test-bench): 
   ```bash 
    git clone git@github.com:Automattic/wpscan-vulnerability-test-bench.git
    cd wpscan-vulnerability-test-bench
    export WPSCANTB_DIR=$(pwd)
    ddev start
   ``` 
5. **Cusor**
   - Visit [https://cursor.sh/download](https://cursor.sh/download) and pick your platform.
   - Linux ``AppImage`` example:
   ```bash
   wget https://downloader.cursor.sh/linux/appImage -O Cursor.AppImage
   chmod +x Cursor.AppImage
   ./Cursor.AppImage
   ```
   Windows and macOS users can run the signed installer from the downloads page.
   - Open `Settings → MCP Servers` in Cursor to make sure the MCPs from the `MCPs/` directory are detected correctly.

## Usage
- Start the agent envroment (Cursor, Copilot) and open a Playground folder.
- Start chatting



## License & Responsible Use

This repository is for educational, authorized security testing. Only run the included tooling in lab environments or against systems where you have explicit permission. When in doubt, err on the side of caution and keep sensitive evidence within the playground directories.