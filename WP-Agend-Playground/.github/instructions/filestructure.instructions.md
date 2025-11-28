---
applyTo: "**"
---

# Templates
- `<project>` stands for the project name. If the user does not indicate one, create one yourself.
    - a project may allready exists, then use that. 
- Suggested directory layout:
  - `all-plugins.txt` (read-only task list)
  - `wp-plugins-sourcecode/` (download and analyses target)
  - `PoCs/<project>_YYYY-MM-DD/` (everything code related)
    - Do not put files directly in the `PoC/` always use subfoulder as indicated.
  - `reports/` (final reports and findings)
  - `analyses/<project>_YYYY-MM-DD/` (anything that does not fall in an other catergorie)
    - Do not put files directly in the `analyses/` always use subfoulder as indicated.
- Never put anything in the root `AgendPlayground/` `/`
- Suggested filename patterns:
  - Report: `reports/<project>_plugin-analysis_YYYY-MM-DD_HH:MM.md` (final summery document)
  - PoC: `PoCs/<project>_YYYY-MM-DD/<plugin-slug>__<vuln-type>__HH:MM.py|rb|sh` (code)
  - analyses: `analyses/<project>_YYYY-MM-DD/<filename>.md` (anything instruction files you genreate during processing)