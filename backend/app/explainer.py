"""AI explanation service.

Enriches findings with a plain-language explanation, real-world impact, and
remediation steps. Provider-agnostic: uses Groq (primary) or Gemini
(alternative) when an API key is present in the environment, and falls back to
built-in per-vulnerability templates so the app works fully offline.

Keys are read from the environment only (GROQ_API_KEY / GEMINI_API_KEY) and are
never logged or hardcoded. Findings are batched per request and cached by a
stable signature so identical findings are never re-sent.
"""

import json
import os
import re
from typing import Optional

import httpx

GROQ_URL = "https://api.groq.com/openai/v1/chat/completions"
GEMINI_URL = "https://generativelanguage.googleapis.com/v1beta/models/{model}:generateContent"

DEFAULT_GROQ_MODEL = "llama-3.3-70b-versatile"
DEFAULT_GEMINI_MODEL = "gemini-1.5-flash"

# In-process cache keyed by a stable finding signature so identical findings are
# explained once and not re-sent to the LLM.
_cache: dict[str, dict] = {}


def clear_cache() -> None:
    _cache.clear()


# --- Per-CWE template explanations (offline fallback) ---------------------------

_TEMPLATES: dict[int, dict] = {
    79: {
        "explanation": "Cross-site scripting (XSS) lets an attacker inject script that runs in other users' browsers in this site's context.",
        "impact": "Attackers can steal session cookies, perform actions as the victim, capture keystrokes, or redirect users to malicious pages.",
        "remediation": "Contextually output-encode all user-controlled data, validate input, and apply a strict Content-Security-Policy.",
    },
    89: {
        "explanation": "SQL injection allows an attacker to alter the database queries the application sends to its backend.",
        "impact": "An attacker can read, modify, or delete arbitrary data, bypass authentication, or in some cases execute commands on the database host.",
        "remediation": "Use parameterized queries / prepared statements, apply least-privilege DB accounts, and validate input.",
    },
    352: {
        "explanation": "Cross-site request forgery (CSRF) tricks an authenticated user's browser into submitting unwanted state-changing requests.",
        "impact": "An attacker can perform actions as the victim (change settings, transfer funds, modify data) without their consent.",
        "remediation": "Require unpredictable anti-CSRF tokens on state-changing requests and set SameSite cookies.",
    },
    918: {
        "explanation": "Server-side request forgery (SSRF) lets an attacker make the server send requests to destinations of their choosing.",
        "impact": "Attackers can reach internal services, cloud metadata endpoints, or exfiltrate data from otherwise unreachable systems.",
        "remediation": "Validate and allowlist outbound destinations, block internal IP ranges, and disable unused URL schemes.",
    },
    693: {
        "explanation": "A protective HTTP security header is missing, weakening the browser-side defenses for this site.",
        "impact": "Missing headers make attacks such as clickjacking, MIME sniffing, or content injection easier to carry out.",
        "remediation": "Set the recommended security headers (CSP, X-Content-Type-Options, X-Frame-Options, etc.) on all responses.",
    },
    1004: {
        "explanation": "A cookie is set without the HttpOnly flag, so client-side scripts can read it.",
        "impact": "If XSS occurs, the session cookie can be stolen, leading to account takeover.",
        "remediation": "Set the HttpOnly flag on session and sensitive cookies.",
    },
    614: {
        "explanation": "A cookie is set without the Secure flag, so it can be transmitted over unencrypted HTTP.",
        "impact": "The cookie may be intercepted on the network, exposing session tokens.",
        "remediation": "Set the Secure flag so cookies are only sent over HTTPS.",
    },
    1275: {
        "explanation": "A cookie lacks a SameSite attribute, so it is sent on cross-site requests.",
        "impact": "This makes the application more susceptible to CSRF.",
        "remediation": "Set SameSite=Lax or SameSite=Strict on cookies as appropriate.",
    },
    319: {
        "explanation": "Sensitive data may be transmitted without enforced transport encryption.",
        "impact": "Network attackers can intercept credentials, tokens, or other sensitive data in transit.",
        "remediation": "Enforce HTTPS everywhere and send the Strict-Transport-Security (HSTS) header.",
    },
    1021: {
        "explanation": "The page can be framed by other sites, enabling clickjacking.",
        "impact": "An attacker can overlay the page to trick users into clicking hidden controls.",
        "remediation": "Send X-Frame-Options: DENY or a frame-ancestors Content-Security-Policy directive.",
    },
    22: {
        "explanation": "Path traversal lets an attacker reference files outside the intended directory.",
        "impact": "Attackers may read sensitive files or, combined with upload, write to unexpected locations.",
        "remediation": "Canonicalize and validate file paths, and reject traversal sequences such as '../'.",
    },
    78: {
        "explanation": "OS command injection allows an attacker to run operating-system commands via the application.",
        "impact": "Full server compromise is often possible, including data theft and lateral movement.",
        "remediation": "Avoid shelling out; use safe APIs, and if unavoidable, strictly validate and escape arguments.",
    },
    94: {
        "explanation": "Code injection lets an attacker get the application to execute attacker-supplied code.",
        "impact": "This typically leads to full application or server compromise.",
        "remediation": "Never evaluate untrusted input; use safe parsers and sandboxing.",
    },
    798: {
        "explanation": "Credentials appear to be hardcoded in the source or configuration.",
        "impact": "Anyone with access to the code or image can use the credentials to access protected systems.",
        "remediation": "Move secrets to environment variables or a secrets manager and rotate the exposed values.",
    },
    200: {
        "explanation": "The application discloses information that could help an attacker.",
        "impact": "Leaked details (versions, paths, stack traces) aid reconnaissance and targeted attacks.",
        "remediation": "Suppress verbose errors and remove unnecessary version/banner disclosure.",
    },
}


def _cwe_int(cwe) -> Optional[int]:
    if not cwe:
        return None
    match = re.search(r"(\d+)", str(cwe))
    return int(match.group(1)) if match else None


def _severity_str(finding) -> str:
    sev = getattr(finding, "severity", None)
    return str(getattr(sev, "value", sev) or "unknown")


def _cache_key(finding) -> str:
    vuln_type = (getattr(finding, "vuln_type", "") or "").lower()
    cwe = str(getattr(finding, "cwe_id", "") or "").lower()
    return f"{vuln_type}|{cwe}"


def _template_for(finding) -> dict:
    cwe = _cwe_int(getattr(finding, "cwe_id", None))
    if cwe in _TEMPLATES:
        return dict(_TEMPLATES[cwe])

    title = getattr(finding, "title", None) or getattr(finding, "vuln_type", None) or "Security finding"
    owasp = getattr(finding, "owasp_category", None)
    engine = getattr(finding, "engine", "scanner")
    existing_remediation = getattr(finding, "remediation", None)
    return {
        "explanation": (
            f"{title} was reported by the {engine} engine"
            + (f", which maps to {owasp}." if owasp else ".")
        ),
        "impact": (
            f"This issue is rated {_severity_str(finding)} severity. Review the affected "
            "location and evidence to assess exploitability and potential data exposure."
        ),
        "remediation": existing_remediation
        or "Review the finding against vendor guidance and apply the recommended secure-coding or configuration fix.",
    }


# --- LLM providers --------------------------------------------------------------


def _provider_from_env() -> Optional[str]:
    if os.getenv("GROQ_API_KEY"):
        return "groq"
    if os.getenv("GEMINI_API_KEY"):
        return "gemini"
    return None


def _build_prompt(reps: list) -> str:
    lines = [
        "You are a senior application security engineer.",
        "For EACH finding below, write a concise plain-language explanation, the "
        "real-world impact, and concrete remediation steps.",
        "Return ONLY a JSON array (no prose, no markdown) where element i "
        "corresponds to finding i. Each element is an object with string keys: "
        '"explanation", "impact", "remediation".',
        "",
    ]
    for i, f in enumerate(reps):
        evidence = (getattr(f, "evidence", "") or "")[:200]
        lines.append(
            f"Finding {i}: type={getattr(f, 'vuln_type', '')}; "
            f"severity={_severity_str(f)}; title={getattr(f, 'title', '')}; "
            f"cwe={getattr(f, 'cwe_id', '')}; owasp={getattr(f, 'owasp_category', '')}; "
            f"evidence={evidence}"
        )
    return "\n".join(lines)


def _extract_json_array(text: str) -> list:
    start = text.find("[")
    end = text.rfind("]")
    if start == -1 or end == -1 or end < start:
        raise ValueError("no JSON array in response")
    return json.loads(text[start : end + 1])


def _call_llm(reps: list, provider: str, timeout: float = 30.0) -> list[dict]:
    prompt = _build_prompt(reps)
    if provider == "groq":
        key = os.environ["GROQ_API_KEY"]
        model = os.getenv("GROQ_MODEL", DEFAULT_GROQ_MODEL)
        resp = httpx.post(
            GROQ_URL,
            headers={"Authorization": f"Bearer {key}"},
            json={
                "model": model,
                "temperature": 0.2,
                "messages": [
                    {"role": "system", "content": "You output only valid JSON."},
                    {"role": "user", "content": prompt},
                ],
            },
            timeout=timeout,
        )
        resp.raise_for_status()
        content = resp.json()["choices"][0]["message"]["content"]
    elif provider == "gemini":
        key = os.environ["GEMINI_API_KEY"]
        model = os.getenv("GEMINI_MODEL", DEFAULT_GEMINI_MODEL)
        resp = httpx.post(
            GEMINI_URL.format(model=model),
            params={"key": key},
            json={"contents": [{"parts": [{"text": prompt}]}]},
            timeout=timeout,
        )
        resp.raise_for_status()
        content = resp.json()["candidates"][0]["content"]["parts"][0]["text"]
    else:
        raise ValueError(f"unknown provider: {provider}")

    parsed = _extract_json_array(content)
    if not isinstance(parsed, list) or len(parsed) != len(reps):
        raise ValueError("LLM response shape did not match the request")

    results = []
    for item in parsed:
        results.append({
            "explanation": (str(item.get("explanation", "")).strip() or None),
            "impact": (str(item.get("impact", "")).strip() or None),
            "remediation": (str(item.get("remediation", "")).strip() or None),
        })
    return results


def _generate(reps: list) -> list[dict]:
    """Produce explanation dicts for representative findings (LLM or template)."""
    provider = _provider_from_env()
    if provider:
        try:
            results = _call_llm(reps, provider)
            # Backfill any fields the model left empty from the template.
            for result, rep in zip(results, reps):
                template = _template_for(rep)
                result["explanation"] = result.get("explanation") or template["explanation"]
                result["impact"] = result.get("impact") or template["impact"]
                result["remediation"] = result.get("remediation") or template["remediation"]
            return results
        except Exception:  # noqa: BLE001 - any failure/rate-limit -> offline templates
            pass
    return [_template_for(rep) for rep in reps]


def explain_findings(findings: list) -> None:
    """Populate explanation / impact / ai_remediation on each finding in place."""
    if not findings:
        return

    keyed: dict[str, list] = {}
    for finding in findings:
        keyed.setdefault(_cache_key(finding), []).append(finding)

    pending = [key for key in keyed if key not in _cache]
    if pending:
        reps = [keyed[key][0] for key in pending]
        results = _generate(reps)
        for key, result in zip(pending, results):
            _cache[key] = result

    for key, group in keyed.items():
        result = _cache[key]
        for finding in group:
            finding.explanation = result.get("explanation")
            finding.impact = result.get("impact")
            finding.ai_remediation = result.get("remediation")
