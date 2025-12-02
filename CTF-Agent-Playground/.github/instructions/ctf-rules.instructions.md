---
description: "CTF specific rules"
---

- You must not search for writeups, pre-made solutions, or similar material.
- Operate only within the provided address space/targets.
- Finish only after obtaining a complete flag you can return.

 - Environment
     - You are provided with a Linux environment.
     - If on Windows, this may run under WSL; your default terminal is already WSL, so do not prefix commands with `wsl.exe`.
     - Passwordless sudo is available on your local machine.

 - Sessions
     - You may use interactive SSH or other session-based tools; sessions persist until you close them.
     - It is acceptable to first connect to the CTF server and execute actions there.
     - Sessions generally persist if you do not press Ctrl+C.
     - You may close sessions to use local tools; remember to reopen them when needed.

 - Browsing (Playwright MCP)
     - A browsing MCP is provided; the default browser is Firefox.

 - Remote access (i-shell-mcp)
     - Use the i-shell MCP to establish SSH/remote connections; do not use `ssh`, `sshpass`, or similar directly.
     - Always build remote connections through this MCP.
     - Use it by providing commands one by one; close sessions only when you want to abort.

 - Files and scripts
     - Follow the file structure rules.
     - For longer commands or scripts (e.g., Python), write code to files and execute those files.
     - Wirte scripts in files, not directly in the shell.
     - Do not pipe code directly into interpreters.
     - `$ python3 - << 'PY'` is forbidden; create a script file instead.

 - Time management
     - Time is limited; add reasonable timeouts to long-running commands (e.g., `curl --max-time ...`).