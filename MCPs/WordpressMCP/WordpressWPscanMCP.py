from __future__ import annotations

import datetime
import os
import time
import subprocess
from typing import Dict, List, Optional

from mcp.server.fastmcp import FastMCP
import json
import asyncio
from pathlib import Path
import logging
import httpx
import zipfile
import shutil
import re
from urllib.parse import urljoin


# Base directory of the WPScan vulnerability test bench checkout
WPSCANTB_DIR = os.getenv("WPSCANTB_DIR", "WP-agent-Playground")

# DDEV app name (optional). When set, we pass --app to ddev for robustness
DDEV_APP = os.getenv("DDEV_APP", None)

# How long to wait between lifecycle steps (in seconds)
SLEEP_SHORT = float(os.getenv("WPSCANTB_SLEEP_SHORT", "2"))
SLEEP_LONG = float(os.getenv("WPSCANTB_SLEEP_LONG", "5"))

# Whether to network-activate plugins on multisite (requires super admin).
# Defaults to False, meaning activate only on the main site so Site Admin works.
NETWORK_ACTIVATE = os.getenv("WPSCANTB_NETWORK_ACTIVATE", "false").strip().lower() in {"1", "true", "yes", "on"}

# WPSCAN submission URL
SUBMIT_BASE_URL = os.getenv("WPSCAN_SUBMIT_BASE_URL", "https://wpscan.com")
SUBMIT_PATH = os.getenv("WPSCAN_SUBMIT_PATH", "/submit")

# Logger name
LOGGER_NAME = "wp-wpscan-mcp"


def setup_logging() -> logging.Logger:
    level_str = os.getenv("WPSCANTB_LOG_LEVEL", "INFO").upper()
    level = getattr(logging, level_str, logging.INFO)
    logger = logging.getLogger(LOGGER_NAME)
    if not logger.handlers:
        logger.setLevel(level)
        formatter = logging.Formatter("%(asctime)s %(levelname)s [%(name)s] %(message)s")
        stream = logging.StreamHandler()
        stream.setFormatter(formatter)
        logger.addHandler(stream)
        # File handler (defaults to WPSCANTB_DIR/logs/wp-wpscan-mcp_<timestamp>.log)
        # Backward compatibility: allow WP_MCP_LOG_FILE as override too
        log_file = (
            os.getenv("WPSCANTB_LOG_FILE")
            or os.getenv("WP_MCP_LOG_FILE")
            or f"{WPSCANTB_DIR}/logs/wp-wpscan-mcp_{time.strftime('%Y-%m-%d_%H:%M')}.log"
        )
        try:
            Path(log_file).parent.mkdir(parents=True, exist_ok=True)
            file_handler = logging.FileHandler(log_file)
            file_handler.setFormatter(formatter)
            logger.addHandler(file_handler)
        except Exception:
            # If file handler setup fails, continue with console-only logging
            pass
    return logger


logger = setup_logging()


mcp = FastMCP("wp-wpscan-mcp")


def _ddev_cmd(args: List[str]) -> subprocess.CompletedProcess:
    base = ["ddev"]
    if DDEV_APP:
        base.extend(["--app", DDEV_APP])
    cmd = base + args
    logger.info("run: %s", " ".join(cmd))
    proc = subprocess.run(
        cmd,
        cwd=WPSCANTB_DIR,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        env={**os.environ, "DDEV_NONINTERACTIVE": "true"},
    )
    return proc


def _wp_cli(args: List[str]) -> subprocess.CompletedProcess:
    # Run wp-cli via ddev wp ...
    proc = _ddev_cmd(["wp", *args])
    return proc


def _require_success(proc: subprocess.CompletedProcess, step: str) -> Dict[str, str]:
    return {
        "step": step,
        "returncode": str(proc.returncode),
        "stdout": proc.stdout,
        "stderr": proc.stderr,
        "cmd": " ".join(proc.args if isinstance(proc.args, list) else [str(proc.args)]),
    }


def _wait_for_wp_readiness(timeout_seconds: int = 60) -> Dict[str, object]:
    # Poll a cheap WP CLI command to check if core is installed and DB reachable
    start = time.time()
    last: Optional[Dict[str, str]] = None
    while time.time() - start < timeout_seconds:
        proc = _wp_cli(["core", "is-installed", "--allow-root"])
        last = _require_success(proc, "core_is_installed")
        if proc.returncode == 0:
            logger.info("wordpress core ready")
            return {"ready": True, "probe": last}
        time.sleep(SLEEP_SHORT)
    logger.warning("wordpress not ready within %ss", timeout_seconds)
    return {"ready": False, "probe": last}


@mcp.tool()
def activate_plugins(slugs: List[str] | str) -> Dict[str, object]:
    """Reset the WPScan test bench by restoring a snapshot, then install + activate plugins.

    - On first run, it creates a 'pristine' snapshot of the clean environment.
    - Subsequent runs restore the 'pristine' snapshot for a fast and complete reset.
    - Accepts a single slug or a list of slugs
    - By default activates per-site on the main site (Site Admin compatible)
    - Set env var `WPSCANTB_NETWORK_ACTIVATE=true` to network-activate instead of single-site
    """
    logger.info("activate request: %s", slugs)
    logger.info("activation mode: %s", "network" if NETWORK_ACTIVATE else "single-site")
    # Normalize input
    plugin_slugs: List[str] = [slugs] if isinstance(slugs, str) else list(slugs)

    steps: List[Dict[str, str]] = []

    # Ensure project directory exists
    if not os.path.isdir(WPSCANTB_DIR):
        return {
            "status": "error",
            "message": "WPSCANTB_DIR does not exist",
            "dir": WPSCANTB_DIR,
        }

    # 1) Try to restore the 'pristine' snapshot for a fast reset.
    proc_restore = _ddev_cmd(["snapshot", "restore", "pristine"])
    steps.append(_require_success(proc_restore, "ddev_restore_snapshot"))

    if proc_restore.returncode != 0:
        logger.warning("Failed to restore 'pristine' snapshot. Assuming first run and creating it.")
        
        # Reset the git repo to a pristine state before creating the snapshot
        proc_git_reset = subprocess.run(["git", "reset", "--hard", "HEAD"], cwd=WPSCANTB_DIR, text=True, capture_output=True)
        steps.append(_require_success(proc_git_reset, "git_reset"))
        proc_git_clean = subprocess.run(["git", "clean", "-fdx"], cwd=WPSCANTB_DIR, text=True, capture_output=True)
        steps.append(_require_success(proc_git_clean, "git_clean"))

        proc_start_initial = _ddev_cmd(["start"])
        steps.append(_require_success(proc_start_initial, "ddev_start_initial"))
        if proc_start_initial.returncode != 0:
            return {"status": "error", "message": "Failed to start ddev for initial snapshot", "steps": steps}

        proc_snapshot = _ddev_cmd(["snapshot", "--name", "pristine"])
        steps.append(_require_success(proc_snapshot, "ddev_snapshot_pristine"))
        if proc_snapshot.returncode != 0:
            return {"status": "error", "message": "Failed to create 'pristine' snapshot", "steps": steps}

    # 2) Ensure the environment is running after snapshot restore
    proc_start = _ddev_cmd(["start"]) 
    steps.append(_require_success(proc_start, "ddev_start_after_restore"))
    if proc_start.returncode != 0:
        return {"status": "error", "message": "Failed to start ddev after snapshot restore", "steps": steps}

    # 3) Wait a bit and then poll readiness
    time.sleep(SLEEP_LONG)
    readiness = _wait_for_wp_readiness(timeout_seconds=120)
    if not readiness.get("ready"):
        return {
            "status": "error",
            "message": "WordPress not ready after timeout",
            "steps": steps,
            "readiness": readiness,
        }

    installed: List[Dict[str, object]] = []
    failed: List[Dict[str, object]] = []

    # 4) Install + activate each plugin (network or single-site based on env switch)
    for slug in plugin_slugs:
        wp_args = ["plugin", "install", "--force", slug]
        if NETWORK_ACTIVATE:
            wp_args.append("--activate-network")
        else:
            wp_args.append("--activate")
        wp_args.append("--allow-root")
        proc_inst = _wp_cli(wp_args)
        result = _require_success(proc_inst, f"install_activate:{slug}")
        if proc_inst.returncode == 0:
            installed.append({"slug": slug, "result": result})
        else:
            failed.append({"slug": slug, "result": result})

    status = "ok" if not failed else ("partial_ok" if installed else "error")
    return {
        "status": status,
        "dir": WPSCANTB_DIR,
        "steps": steps,
        "readiness": readiness,
        "installed": installed,
        "failed": failed,
        "activation_mode": "network" if NETWORK_ACTIVATE else "single-site",
    }


@mcp.tool()
async def plugins_download_sources(
    slugs: List[str],
    dest_dir: str = "/home/user/agent-bughunt/agentPlayground/wp-plugins-sourcecode",
    concurrency: int = 16,
    skip_existing: bool = True,
    remove_zip: bool = True,
    log_path: Optional[str] = None,
    progress_interval: float = 1.0,
) -> Dict[str, object]:
    """Download and extract plugin source code for the given slugs into dest_dir.

    Optimized for large lists via async concurrency and streaming.
    - slugs: list of plugin slugs from wordpress.org
    - dest_dir: directory to store extracted sources
    - concurrency: max concurrent downloads/extractions
    - skip_existing: if True, skip slugs with non-empty extract dir
    - remove_zip: delete zip file after extraction
    """
    base_url = "https://downloads.wordpress.org/plugin/"
    dest_path = Path(dest_dir)
    dest_path.mkdir(parents=True, exist_ok=True)

    semaphore = asyncio.Semaphore(max(1, concurrency))
    downloaded: List[Dict[str, str]] = []
    skipped: List[Dict[str, str]] = []
    errors: List[Dict[str, str]] = []
    completed: int = 0

    # Structured NDJSON logging
    log_fp = open(log_path, "a", encoding="utf-8") if log_path else None
    log_lock = asyncio.Lock()

    async def write_log(event: Dict[str, object]) -> None:
        if not log_fp:
            return
        event_with_ts = {"ts": time.time(), **event}
        async with log_lock:
            try:
                log_fp.write(json.dumps(event_with_ts) + "\n")
                log_fp.flush()
            except Exception:
                pass

    def is_dir_nonempty(path: Path) -> bool:
        if not path.exists():
            return False
        try:
            next(path.iterdir())
            return True
        except StopIteration:
            return False

    def extract_zip(zip_path: Path, extract_dir: Path) -> None:
        if extract_dir.exists():
            shutil.rmtree(extract_dir, ignore_errors=True)
        extract_dir.mkdir(parents=True, exist_ok=True)
        with zipfile.ZipFile(zip_path, "r") as zf:
            zf.extractall(extract_dir)

    timeout = httpx.Timeout(60.0)
    limits = httpx.Limits(
        max_keepalive_connections=concurrency,
        max_connections=max(concurrency * 2, 32),
    )
    client = httpx.AsyncClient(follow_redirects=True, timeout=timeout, limits=limits)

    logger.info(
        "download batch start: total=%s, dest=%s, concurrency=%s, skip_existing=%s",
        len(slugs), str(dest_path), concurrency, skip_existing,
    )
    await write_log({
        "event": "start",
        "total_slugs": len(slugs),
        "dest_dir": str(dest_path),
        "concurrency": concurrency,
        "skip_existing": skip_existing,
        "remove_zip": remove_zip,
    })

    async def process_slug(slug: str) -> Dict[str, object]:
        nonlocal completed
        async with semaphore:
            extract_dir = dest_path / slug
            if skip_existing and is_dir_nonempty(extract_dir):
                info = {"slug": slug, "extract_dir": str(extract_dir), "reason": "exists"}
                skipped.append(info)
                logger.info("skip existing: %s", slug)
                await write_log({"event": "skipped", **info})
                return {"skipped": info}

            candidates = [f"{slug}.latest-stable.zip", f"{slug}.zip"]
            last_error: str | None = None

            for filename in candidates:
                url = base_url + filename
                logger.info("download start: %s -> %s", slug, url)
                await write_log({"event": "download_start", "slug": slug, "url": url})
                for attempt in range(3):
                    try:
                        resp = await client.get(url)
                        if resp.status_code == 200:
                            tmp_zip = dest_path / f"{slug}.zip.part"
                            final_zip = dest_path / f"{slug}.zip"

                            total_bytes = int(resp.headers.get("Content-Length", 0) or 0)
                            downloaded_bytes = 0
                            last_progress = time.monotonic()

                            with tmp_zip.open("wb") as f:
                                async for chunk in resp.aiter_bytes(chunk_size=1024 * 1024):
                                    if not chunk:
                                        continue
                                    f.write(chunk)
                                    downloaded_bytes += len(chunk)
                                    now = time.monotonic()
                                    if (now - last_progress) >= max(0.05, progress_interval):
                                        await write_log({
                                            "event": "download_progress",
                                            "slug": slug,
                                            "downloaded": downloaded_bytes,
                                            "total": total_bytes,
                                            "percent": (downloaded_bytes / total_bytes * 100.0) if total_bytes else None,
                                        })
                                        last_progress = now

                            tmp_zip.rename(final_zip)
                            await write_log({
                                "event": "download_complete",
                                "slug": slug,
                                "size": downloaded_bytes,
                                "total": total_bytes,
                            })

                            await write_log({"event": "extract_start", "slug": slug})
                            await asyncio.to_thread(extract_zip, final_zip, extract_dir)
                            await write_log({"event": "extract_complete", "slug": slug, "extract_dir": str(extract_dir)})
                            logger.info("extracted: %s", slug)

                            if remove_zip:
                                try:
                                    final_zip.unlink(missing_ok=True)
                                    await write_log({"event": "zip_deleted", "slug": slug})
                                except Exception:
                                    pass

                            info = {
                                "slug": slug,
                                "zip_url": url,
                                "extract_dir": str(extract_dir),
                            }
                            downloaded.append(info)
                            await write_log({"event": "success", **info})
                            logger.info("download success: %s", slug)

                            completed += 1
                            await write_log({
                                "event": "overall",
                                "completed": completed,
                                "downloaded_count": len(downloaded),
                                "skipped_count": len(skipped),
                                "error_count": len(errors),
                                "total": len(slugs),
                            })
                            return {"downloaded": info}
                        else:
                            last_error = f"HTTP {resp.status_code} for {url}"
                            break  # next candidate
                    except Exception as e:
                        last_error = f"{type(e).__name__}: {e}"
                        await asyncio.sleep(0.5 * (attempt + 1))
                # try next candidate

            err = {"slug": slug, "error": last_error or "Unknown error"}
            errors.append(err)
            await write_log({"event": "error", **err})
            logger.error("download failed: %s -> %s", slug, err.get("error"))

            completed += 1
            await write_log({
                "event": "overall",
                "completed": completed,
                "downloaded_count": len(downloaded),
                "skipped_count": len(skipped),
                "error_count": len(errors),
                "total": len(slugs),
            })
            return {"error": err}

    # Schedule tasks in batches to avoid creating too many tasks at once
    tasks: List[asyncio.Task] = []
    for slug in slugs:
        tasks.append(asyncio.create_task(process_slug(slug)))

    # Gather while allowing cancellations to propagate correctly
    await asyncio.gather(*tasks, return_exceptions=False)

    await write_log({
        "event": "done",
        "downloaded_count": len(downloaded),
        "skipped_count": len(skipped),
        "error_count": len(errors),
        "total": len(slugs),
    })
    logger.info(
        "download batch done: downloaded=%s skipped=%s errors=%s total=%s",
        len(downloaded), len(skipped), len(errors), len(slugs),
    )

    await client.aclose()
    if log_fp:
        try:
            log_fp.close()
        except Exception:
            pass

    return {
        "status": "ok",
        "downloaded": downloaded,
        "skipped": skipped,
        "errors": errors,
        "log_path": log_path,
    }


@mcp.tool()
def plugins_delete_sources(slugs: List[str], dest_dir: str = "/home/user/agent-bughunt/wp-plugins-sorcecode") -> Dict[str, object]:
    """Delete extracted plugin source directories for the given slugs from dest_dir.

    - slugs: list of plugin slugs
    - dest_dir: local directory that stores extracted sources
    """
    dest_path = Path(dest_dir)
    removed: List[Dict[str, str]] = []
    errors: List[Dict[str, str]] = []

    for slug in slugs:
        target = dest_path / slug
        if not target.exists():
            errors.append({"slug": slug, "error": "not found"})
            continue
        try:
            shutil.rmtree(target)
            removed.append({"slug": slug, "path": str(target)})
        except Exception as e:
            errors.append({"slug": slug, "error": f"{type(e).__name__}: {e}"})

    logger.info("delete sources: removed=%s errors=%s", len(removed), len(errors))
    return {"status": "ok", "removed": removed, "errors": errors}


VULNERABILITY_TYPE_TO_CODE = {
    "AUTHBYPASS": "1",
    "BYPASS": "2",
    "CSRF": "3",
    "FPD": "4",
    "LFI": "5",
    "MULTI": "6",
    "RCE": "7",
    "REDIRECT": "8",
    "RFI": "9",
    "SQLI": "10",
    "SSRF": "11",
    "UNKNOWN": "12",
    "UPLOAD": "13",
    "XSS": "14",
    "XXE": "15",
    "DOS": "16",
    "PRIVESC": "17",
    "OBJECT INJECTION": "18",
    "BACKDOOR": "19",
    "TRAVERSAL": "20",
    "INJECTION": "21",
    "SENSITIVE DATA DISCLOSURE": "22",
    "IDOR": "23",
    "ACCESS CONTROLS": "24",
    "INSUFFICIENT CRYPTOGRAPHY": "25",
    "FILE DELETION": "26",
    "CROSS FRAME SCRIPTING": "27",
    "CSV INJECTION": "28",
    "CONTENT INJECTION": "29",
    "FILE DOWNLOAD": "30",
    "RACE CONDITION": "31",
    "COMMAND INJECTION": "32",
    "NO AUTHORISATION": "33",
    "INCORRECT AUTHORISATION": "34",
    "TAB NABBING": "35",
    "CACHE POISONING": "36",
    "SPOOFING": "37",
}
@mcp.tool()
def get_possible_vulnerability_types() -> List[str]:
    return list(VULNERABILITY_TYPE_TO_CODE.keys())

REQUIRED_ACCESS_ALLOWED = {
    "unauthenticated",
    "subscriber",
    "contributor",
    "author",
    "editor",
    "admin",
    "custom",
}
@mcp.tool()
def get_possible_required_access_levels() -> List[str]:
    return list(REQUIRED_ACCESS_ALLOWED)


def _normalize_vuln_type(value: str) -> Optional[str]:
    if value is None:
        return None
    val = str(value).strip()
    if val.isdigit() and val in set(VULNERABILITY_TYPE_TO_CODE.values()):
        return val
    key = val.upper()
    # Normalize multiple spaces
    key = re.sub(r"\s+", " ", key)
    return VULNERABILITY_TYPE_TO_CODE.get(key)


def _normalize_required_access(value: str) -> Optional[str]:
    if value is None:
        return None
    val = str(value).strip().lower()
    return val if val in REQUIRED_ACCESS_ALLOWED else None


@mcp.tool()
async def submit_finding(
    # Your Details
    submitter_name: Optional[str] = None,
    original_researcher: Optional[bool] = None,
    researcher_name: Optional[str] = None,
    submitter_email: Optional[str] = None,
    opt_in_to_emails: Optional[bool] = None,
    submitter_website: Optional[str] = None,
    submitter_twitter: Optional[str] = None,
    # Vulnerability Details
    title: str = "",
    vulnerability_type: str = "",
    affected_plugins: Optional[List[str]] = None,
    affected_themes: Optional[List[str]] = None,
    min_required_access: str = "",
    published_date: Optional[datetime.date] = None,
    description: str = "",
    proof_of_concept: str = "",
    video_urls: Optional[List[str]] = None,
    reference_urls: Optional[List[str]] = None,
    vendor_notified: Optional[bool] = None,
    requires_cve: Optional[bool] = None,
    terms_accepted: bool = False,
    dry_run: bool = False,
) -> Dict[str, object]:
    """
    Submit a vulnerability finding to WPScan (best-effort form POST to wpscan.com/submit).

    Parameters mirror the website's form fields.
    vulnerability_type must be one of the allowed types; min_required_access must be one of the allowed access levels.
    proof_of_concept should be a cURL command, raw request, or other minimal PoC.
    terms_accepted must be True to submit.
    dry_run can be set to True to return the constructed payload without submitting.
    """
    url = urljoin(SUBMIT_BASE_URL, SUBMIT_PATH)
    headers = {
        "User-Agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122 Safari/537.36",
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        "Accept-Language": "en-US,en;q=0.9",
        "Referer": url,
    }

    logger.info("submit_finding: start url=%s", url)

    if not terms_accepted:
        logger.warning("submit_finding: validation failed - terms_accepted is False")
        return {"status": "error", "stage": "validate", "message": "terms_accepted must be True"}

    # Validate and normalize enums
    vuln_code = _normalize_vuln_type(vulnerability_type)
    if not vuln_code:
        logger.warning("submit_finding: invalid vulnerability_type '%s'", vulnerability_type)
        return {
            "status": "error",
            "stage": "validate",
            "message": "Invalid vulnerability_type",
            "allowed_types": list(VULNERABILITY_TYPE_TO_CODE.keys()),
        }
    access_norm = _normalize_required_access(min_required_access)
    if not access_norm:
        logger.warning("submit_finding: invalid min_required_access '%s'", min_required_access)
        return {
            "status": "error",
            "stage": "validate",
            "message": "Invalid min_required_access",
            "allowed_access": sorted(list(REQUIRED_ACCESS_ALLOWED)),
        }

    logger.info("submit_finding: validated vuln_type_code=%s required_access=%s", vuln_code, access_norm)

    # Dates: ensure YYYY-MM-DD
    published_date_str = ""
    if published_date:
        if isinstance(published_date, datetime.date):
            published_date_str = published_date.isoformat()
        else:
            published_date_str = str(published_date)

    # Repeater/arrays formatting
    affected_plugins_str = "\n".join(affected_plugins or [])
    affected_themes_str = "\n".join(affected_themes or [])
    video_urls_str = "\n".join(video_urls or [])
    reference_urls_str = "\n".join(reference_urls or [])

    timeout = httpx.Timeout(30.0)
    async with httpx.AsyncClient(follow_redirects=True, timeout=timeout, headers=headers) as client:
        try:
            logger.info("submit_finding: GET %s", url)
            get_resp = await client.get(url)
        except Exception as e:
            logger.error("submit_finding: GET failed: %s", e)
            return {"status": "error", "stage": "get_form", "error": f"{type(e).__name__}: {e}"}

        logger.info("submit_finding: GET status=%s", get_resp.status_code)
        if get_resp.status_code != 200:
            logger.warning("submit_finding: unexpected GET status %s", get_resp.status_code)
            return {"status": "error", "stage": "get_form", "http_status": get_resp.status_code}

        html = get_resp.text or ""

        # Find form action
        form_action_match = re.search(r"<form[^>]*action=\"([^\"]+)\"[^>]*>", html, flags=re.I)
        action_path = form_action_match.group(1) if form_action_match else SUBMIT_PATH
        post_url = urljoin(SUBMIT_BASE_URL, action_path)
        logger.info("submit_finding: post_url=%s", post_url)

        # Hidden inputs (e.g., CSRF)
        hidden_inputs = dict(
            re.findall(r"<input[^>]*type=\"hidden\"[^>]*name=\"([^\"]+)\"[^>]*value=\"([^\"]*)\"[^>]*>", html, flags=re.I)
        )
        logger.info("submit_finding: hidden_inputs count=%d keys=%s", len(hidden_inputs), ",".join(list(hidden_inputs.keys())))

        # Construct payload strictly following form names
        payload: Dict[str, object] = {}
        payload.update(hidden_inputs)

        # Your Details
        if submitter_name is not None:
            payload["submitter_name"] = submitter_name
        if original_researcher is not None:
            if original_researcher:
                payload["original_researcher"] = "true"
        if researcher_name is not None:
            payload["researcher_name"] = researcher_name
        if submitter_email is not None:
            payload["submitter_email"] = submitter_email
        if opt_in_to_emails is not None:
            if opt_in_to_emails:
                payload["optInToEmails"] = "true"
        if submitter_website is not None:
            payload["submitter_website"] = submitter_website
        if submitter_twitter is not None:
            payload["submitter_twitter"] = submitter_twitter

        # Vulnerability Details
        payload["title"] = title
        payload["vuln_type"] = vuln_code
        if affected_plugins_str:
            payload["affected_plugins"] = affected_plugins_str
        if affected_themes_str:
            payload["affected_themes"] = affected_themes_str
        payload["required_access"] = access_norm
        if published_date_str:
            payload["published_date"] = published_date_str
        payload["description"] = description
        payload["poc"] = proof_of_concept
        if video_urls_str:
            payload["video_urls"] = video_urls_str
        if reference_urls_str:
            payload["reference_urls"] = reference_urls_str
        if vendor_notified:
            payload["vendor_notified"] = "true"
        if requires_cve:
            payload["requires_cve"] = "true"
        # Required terms checkbox
        payload["terms_accepted"] = "true"

        payload_keys = sorted(list(payload.keys()))
        logger.info("submit_finding: payload_keys count=%d", len(payload_keys))

        # Captcha detection hint
        if re.search(r"captcha|hcaptcha|g-recaptcha", html, flags=re.I):
            logger.warning("submit_finding: captcha detected on form; automated submission may fail")

        if dry_run:
            logger.info("submit_finding: dry_run enabled, returning constructed payload")
            return {
                "status": "dry_run",
                "payload": payload,
                "payload_keys": sorted(list(payload.keys())),
                "post_url": post_url,
                "hidden": hidden_inputs,
                "snippet": get_resp.text[:1000],
                "captcha_hint": bool(re.search(r"captcha|hcaptcha|g-recaptcha", html, flags=re.I)),
            }

        try:
            logger.info("submit_finding: POST %s", post_url)
            post_resp = await client.post(
                post_url,
                data=payload,
                headers={"Content-Type": "application/x-www-form-urlencoded", "Referer": url},
            )
        except Exception as e:
            logger.error("submit_finding: POST failed: %s", e)
            return {
                "status": "error",
                "stage": "submit",
                "post_url": post_url,
                "error": f"{type(e).__name__}: {e}",
                "hidden": hidden_inputs,
            }

        ok = 200 <= post_resp.status_code < 400
        body_snippet = (post_resp.text or "")[:1000]
        location = post_resp.headers.get("Location")
        logger.info("submit_finding: POST status=%s location=%s", post_resp.status_code, location)
        success = ok and ("thank" in body_snippet.lower() or "received" in body_snippet.lower())

        result = {
            "status": "ok" if success else ("maybe_ok" if ok else "error"),
            "http_status": post_resp.status_code,
            "post_url": post_url,
            "hidden": hidden_inputs,
            "payload_keys": sorted(list(payload.keys())),
            "snippet": body_snippet,
            "captcha_hint": bool(re.search(r"captcha|hcaptcha|g-recaptcha", html, flags=re.I)),
        }
        if not success:
            result["note"] = "Automated submission may be blocked by anti-bot protections. Consider manual submission."
        return result


def main() -> None:
    mcp.run()


if __name__ == "__main__":
    main()
