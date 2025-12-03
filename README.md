# Hunting vulnerabilities with simple LLM agents - Workshop Kit

This repository bundles everything we need for the hunting vulnerabilities with simple LLM agents
workshop. 

## Repository Layout

- `CTF-agent-Playground/` — self-contained capture-the-flag style exercises (race-condition lab, survey challenge, forensics artifacts, helper scripts, etc.). Use these for fast-paced demos or individual drills.
- `WP-agent-Playground/` — WordPress assessment workspace with analyses, PoCs, and formal reports. 
- `MCPs/` — standalone MCP servers. Each folder is an installable Python package (managed with `uv`) that exposes a specialized tool:
  - `CheckFlagMCP` verifies submitted flags over HTTP if given session cookie.
  - `IShellMCP` provides incremental shell access for remote exploitation.
  - `MetasploitMCP` bridges Cursor to Metasploit RPC (list exploits, run modules, manage sessions, generate payloads).
  - `WordpressMCP` automates plugin downloads, activation, scanning, and reporting inside a standardized WordPress bench.


## Getting Started

1. **Clone**
   ```bash
   git clone https://github.com/Shepherd-ITSec/agent-bughunt.git
   cd agent-bughunt
   ```
2. **Python toolchain**  
   - Install [uv](https://docs.astral.sh/uv/getting-started/installation/) (recommended) or ensure Python ≥3.10 is available.  
   - For a specific MCP, run `uv sync` (or `pip install -r requirements.txt`) inside that MCP’s folder to make it available.
3. **Metasploit (optional)**  
   - If you like to use the `MetasploitMCP`, install methasploid and start the API server with `msfrpcd -P pass123 -a 127.0.0.1 -p 55553 -S`.
4. **Wordpress (optional)**
   - If you would like to test wordpress plugins you need to setup a wordpress environment
   - Install [docker](https://docs.ddev.com/en/stable/users/install/docker-installation/)
   - Install [ddev](https://docs.ddev.com/en/stable/users/install/ddev-installation/)
   - Clone the [WPScan Vulnerability Testbench](https://github.com/Automattic/wpscan-vulnerability-test-bench): 
   ```bash 
    git clone git@github.com:Automattic/wpscan-vulnerability-test-bench.git
    cd wpscan-vulnerability-test-bench
    export WPSCANTB_DIR=$(pwd)
    ddev start
   ``` 
5. **Cursor (optional)**
   - Visit [https://cursor.sh/download](https://cursor.sh/download) and pick your platform.
   - Linux ``AppImage`` example:
   ```bash
   wget https://downloader.cursor.sh/linux/appImage -O Cursor.AppImage
   chmod +x Cursor.AppImage
   ./Cursor.AppImage
   ```
   Windows and macOS users can run the signed installer from the downloads page.
   - Open `Settings → MCP Servers` in Cursor to make sure the MCPs from the `MCPs/` directory are detected correctly.

5. **Copilot + SURF-Willma models (alternative)**
   - Alternativly you can uses the models provided by SURF together with github copilot
     - Info: Theese models are not as strong as the commercial once
   - Therfore [install Visual Studio Code Insiders](https://code.visualstudio.com/insiders/)
   - Click on the right in the copilot window on `select model` and singe-in with any account. 

   - Click  on the right in the copilot window on `Auto` and select `Manage Models`
   - Click `+ Add Models..` and select `OpenAPI compatible`
   - Use the following specifications in this order, followed by the API key
   ```json
      "openai/gpt-oss-120b": {
         "name": "SURF-gpt-oss-120b",
         "url": "https://willma.surf.nl/api/v0/chat/completions",
         "toolCalling": true,
         "vision": true,
         "thinking": true,
         "requiresAPIKey": true,
         "maxInputTokens": 128000,
         "maxOutputTokens": 4096
      },

   ```
   - Double click the model in the `OpenAI Compatible` tab to un-hide it
   - Select the model to use by clicking on `Auto` in the copilot chat and choosing it
   - Press the wheel symbol on top of the copilot window and click `MCP Servers` to make sure the MCPs from the `MCPs/` directory are detected correctly
  
## Usage
- Start the agent environment (Cursor, Copilot) and open the fitting Playground folder of this repo.
- Start chatting
  - You may for example copy the text of a simple CTF task into the chat window and tell the agent to solve it.



## License & Responsible Use

This repository is for educational, authorized security testing. Only run the included tooling in lab environments or against systems where you have explicit permission. When in doubt, err on the side of caution and keep sensitive evidence within the playground directories.