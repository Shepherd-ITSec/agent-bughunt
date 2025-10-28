from __future__ import annotations

import logging
from typing import Any, Awaitable, Callable, Dict, Optional

import httpx  # type: ignore[reportMissingImports]
from mcp.server.fastmcp import FastMCP  # type: ignore[reportMissingImports]


LOGGER_NAME = "check-flag-mcp"


def setup_logging() -> logging.Logger:
    logger = logging.getLogger(LOGGER_NAME)
    if not logger.handlers:
        logger.setLevel(logging.INFO)
        formatter = logging.Formatter("%(asctime)s %(levelname)s [%(name)s] %(message)s")
        stream_handler = logging.StreamHandler()
        stream_handler.setFormatter(formatter)
        logger.addHandler(stream_handler)
    return logger


logger = setup_logging()

mcp = FastMCP("check-flag-mcp")


async def _check_studsec_pwncrates(
    flag: str,
    *,
    base_url: str,
    challenge_id: int,
    cookie_session: str,
    user_agent: Optional[str] = None,
    referer: Optional[str] = None,
    timeout_seconds: float = 15.0,
) -> Dict[str, Any]:
    """Submit a flag to studsec/pwncrates instance.

    Expects a session cookie and will POST form-encoded data: flag=<flag> to
    {base_url}/api/challenges/submit/{challenge_id}.
    """
    submit_url = f"{base_url.rstrip('/')}/api/challenges/submit/{challenge_id}"
    headers: Dict[str, str] = {
        "Accept": "application/json, text/html",
        "Content-Type": "application/x-www-form-urlencoded",
        "Cookie": "session=" + cookie_session,
        "Connection": "keep-alive",
        "Pragma": "no-cache",
        "Cache-Control": "no-cache",
    }
    if user_agent:
        headers["User-Agent"] = user_agent
    if referer:
        headers["Referer"] = referer

    data = {"flag": flag}

    timeout = httpx.Timeout(timeout_seconds)
    async with httpx.AsyncClient(timeout=timeout, follow_redirects=True) as client:
        try:
            resp = await client.post(submit_url, headers=headers, data=data)
        except Exception as e:
            return {
                "status": "error",
                "platform": "studsec",
                "error": f"{type(e).__name__}: {e}",
            }

    response_text: str = resp.text or ""
    response_json: Optional[Dict[str, Any]] = None
    try:
        response_json = resp.json()
    except Exception:
        response_json = None

    # Heuristics for result determination; include raw server response for transparency
    is_correct: Optional[bool] = None
    message: Optional[str] = None
    if isinstance(response_json, dict):
        # Common patterns: {"correct": true|false} or {"message": "Correct!"}
        if "correct" in response_json and isinstance(response_json["correct"], bool):
            is_correct = response_json["correct"]
        if not message and isinstance(response_json.get("status"), str):
            message = response_json.get("status")

    if is_correct is None:
        lowered = response_text.lower()
        if "correct" in lowered and "incorrect" not in lowered:
            is_correct = True
        elif "incorrect" in lowered or "wrong" in lowered:
            is_correct = False

    result: str = "unknown"
    if is_correct is True:
        result = "correct"
    elif is_correct is False:
        result = "incorrect"

    return {
        "status": "ok",
        "platform": "studsec",
        "result": result,
        "http_status": resp.status_code,
        "status_message": message,
        "response_json": response_json,
        "response_text": response_text[:4000],
        "url": submit_url,
    }


PlatformChecker = Callable[[str], Awaitable[Dict[str, Any]]]


@mcp.tool()
async def check_flag(
    platform: str,
    flag: str,
    options: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    """Check a CTF flag against a specific platform.

    - platform: which platform implementation to use (e.g., "studsec", "pwncrates").
    - flag: the flag string to submit.
    - options: platform-specific options as a dict.

    Platform "studsec" (also alias: "pwncrates") options:
      - base_url (str, required): e.g., https://ctf.studsec.nl
      - challenge_id (int, required): numeric challenge id used in submit endpoint
      - cookie_session (str, required): Cookie header value containing the session
      - user_agent (str, optional)
      - referer (str, optional)
      - timeout_seconds (float, optional)
    """
    opts: Dict[str, Any] = options or {}
    name = platform.strip().lower()

    if name in {"studsec", "pwncrates"}:
        missing: list[str] = []
        base_url = opts.get("base_url")
        challenge_id = opts.get("challenge_id")
        cookie_session = opts.get("cookie_session")
        if not base_url:
            missing.append("base_url")
        if challenge_id is None:
            missing.append("challenge_id")
        if not cookie_session:
            missing.append("cookie_session")
        if missing:
            return {
                "status": "error",
                "error": f"missing required options: {', '.join(missing)}",
                "platform": name,
            }

        try:
            cid = int(str(challenge_id))
        except Exception:
            return {
                "status": "error",
                "error": "challenge_id must be an integer",
                "platform": name,
            }

        return await _check_studsec_pwncrates(
            flag,
            base_url=str(base_url),
            challenge_id=cid,
            cookie_session=str(cookie_session),
            user_agent=opts.get("user_agent"),
            referer=opts.get("referer"),
            timeout_seconds=float(opts.get("timeout_seconds", 15.0)),
        )

    return {
        "status": "error",
        "error": f"unsupported platform: {platform}",
        "known_platforms": ["studsec", "pwncrates"],
    }


def main() -> None:
    mcp.run()


if __name__ == "__main__":
    main()
