"""Low-impact CTF workflow and trust-boundary analysis.

This module discovers same-origin links, forms, hidden workflow fields, JSON
keys, URL-like parameters, identity-provider hints, and response-side proxy
headers. Automatic analysis is read-only; optional --guided mode can submit one
operator-selected form after an explicit confirmation. It never makes SSRF
callbacks or sends ambiguous HTTP framing requests.
"""

from __future__ import annotations

import json
import re
from collections import defaultdict
from typing import Any, Dict, Iterable, List, Optional, Set
from urllib.parse import parse_qsl, urljoin, urlparse

from bs4 import BeautifulSoup

from .base import BaseModule

MAX_PAGES = 6
MAX_SCRIPTS = 3
MAX_BODY_CHARS = 250_000

TOKEN_NAME_RE = re.compile(r"csrf|xsrf|authenticity|nonce|ticket|state|_token|challenge", re.I)
PRIVILEGE_NAME_RE = re.compile(
    r"(^|[_-])(admin|role|is_admin|isadmin|permission|privilege|access_level)([_-]|$)", re.I
)
IDENTITY_NAME_RE = re.compile(
    r"issuer|jwks|openid|oauth|oidc|callback|redirect|return_to|identity|provider|metadata|"
    r"endpoint|url|uri|host|domain|client_id|audience|token|ticket|api[_-]?key|secret|credential",
    re.I,
)
URL_VALUE_RE = re.compile(r"^(https?://|//)[^\s]+$", re.I)

FRONT_PROXY_HEADERS = (
    "Via", "X-Cache", "X-Served-By", "CF-Ray", "X-Proxy", "X-Envoy-Upstream-Service-Time",
    "X-Backend-Server", "X-Upstream", "X-Request-ID", "Forwarded",
)


class FlowAnalysis(BaseModule):
    name = "Workflow / Form / Identity Analysis"

    def run(self) -> None:
        origin = self.config.base_url.rstrip("/")
        queue: List[str] = [origin]
        seen_pages: Set[str] = set()
        seen_scripts: Set[str] = set()
        forms: List[Dict[str, Any]] = []
        runtime_forms: List[Dict[str, Any]] = []
        parameters: Dict[str, List[str]] = defaultdict(list)
        identity_hints: List[Dict[str, str]] = []
        js_endpoints: Set[str] = set()
        proxy_headers: Dict[str, str] = {}
        page_count = 0

        self.log("Inspecting same-origin pages; automatic form analysis is read-only")

        while queue and page_count < MAX_PAGES and self._can_continue():
            url = queue.pop(0)
            if url in seen_pages or not self.rm.is_same_origin(url):
                continue
            seen_pages.add(url)
            response = self.rm.get(url, allow_redirects=True)
            if response is None:
                continue
            page_count += 1
            final_url = response.url or url
            self.reporter.add_endpoint(final_url)

            if page_count == 1:
                for header in FRONT_PROXY_HEADERS:
                    value = response.headers.get(header)
                    if value:
                        proxy_headers[header] = value[:200]
                for header in ("Content-Length", "Transfer-Encoding", "Connection", "Keep-Alive"):
                    value = response.headers.get(header)
                    if value:
                        proxy_headers[f"HTTP framing: {header}"] = value[:200]
                server = response.headers.get("Server")
                powered = response.headers.get("X-Powered-By")
                if server and powered and server.lower() not in powered.lower():
                    proxy_headers["Server / X-Powered-By"] = f"{server} / {powered}"[:200]

            content_type = response.headers.get("Content-Type", "").lower()
            body = (response.text or "")[:MAX_BODY_CHARS]

            # Discover query parameters from the page URL.
            for name, _value in parse_qsl(urlparse(final_url).query, keep_blank_values=True):
                if name and final_url not in parameters[name]:
                    parameters[name].append(final_url)
                if name and (IDENTITY_NAME_RE.search(name) or PRIVILEGE_NAME_RE.search(name)):
                    identity_hints.append({
                        "source": "query parameter",
                        "name": name[:120],
                        "action": final_url,
                        "note": "Privilege or identity-related parameter observed in the URL; no value was changed.",
                    })

            if "json" in content_type or body.lstrip().startswith(("{", "[")):
                self._inspect_json(body, final_url, parameters, identity_hints)
                continue

            if "html" not in content_type and "<html" not in body[:1000].lower():
                continue

            soup = BeautifulSoup(body, "html.parser")

            # CSRF/ticket meta tags are common when a page does not use hidden inputs.
            for meta in soup.find_all("meta"):
                meta_name = str(meta.get("name") or meta.get("property") or "")
                meta_value = str(meta.get("content") or "")
                if meta_name and TOKEN_NAME_RE.search(meta_name):
                    self.log(
                        f"Workflow meta token detected: {meta_name} "
                        f"(value length={len(meta_value)}; value withheld)"
                    )
                    if getattr(self.config, "show_workflow_tokens", False) and meta_value:
                        self.log(f"Workflow meta token {meta_name}: {meta_value[:512]}", style="yellow")

            # Links are only queued when they remain on the exact origin.
            for anchor in soup.find_all("a", href=True):
                candidate = urljoin(final_url, str(anchor.get("href", "")).strip())
                if self.rm.is_same_origin(candidate):
                    clean = self._without_fragment(candidate)
                    if clean not in seen_pages and clean not in queue and len(queue) < MAX_PAGES:
                        queue.append(clean)

            # Extract forms and inputs without submitting or changing their values.
            for form_index, form in enumerate(soup.find_all("form"), start=1):
                action = urljoin(final_url, str(form.get("action") or final_url))
                method = str(form.get("method") or "GET").upper()
                fields: List[Dict[str, Any]] = []
                runtime_fields: List[Dict[str, Any]] = []
                for control in form.find_all(["input", "select", "textarea", "button"]):
                    name = str(control.get("name") or "").strip()
                    if not name:
                        continue
                    kind = str(control.get("type") or control.name).lower()
                    value = str(control.get("value") or "")
                    if control.name == "textarea":
                        value = control.get_text() or value
                    elif control.name == "select":
                        selected = control.find("option", selected=True) or control.find("option")
                        value = str(selected.get("value") if selected and selected.has_attr("value") else selected.get_text(strip=True) if selected else value)
                    is_hidden = kind == "hidden"
                    token_like = bool(TOKEN_NAME_RE.search(name))
                    sensitive_value = token_like or kind == "password" or bool(
                        re.search(r"api[_-]?key|secret|credential|authorization", name, re.I)
                    )
                    checked = control.has_attr("checked")
                    if kind in ("checkbox", "radio") and not checked:
                        value_for_runtime = ""
                    else:
                        value_for_runtime = value
                    field = {
                        "name": name[:120],
                        "type": kind[:40],
                        "hidden": is_hidden,
                        "required": control.has_attr("required"),
                        "value_present": bool(value),
                        "value_length": len(value),
                        "value_preview": self._safe_preview(value) if value and not sensitive_value else "[redacted]",
                    }
                    fields.append(field)
                    runtime_fields.append({
                        "name": name,
                        "type": kind,
                        "value": value_for_runtime if not (kind == "password" or re.search(r"api[_-]?key|secret|credential|authorization", name, re.I)) else "",
                        "sensitive": sensitive_value,
                        "hidden": is_hidden,
                        "required": control.has_attr("required"),
                    })
                    parameters[name].append(action)
                    if IDENTITY_NAME_RE.search(name):
                        identity_hints.append({
                            "source": "form field",
                            "name": name[:120],
                            "action": action,
                            "note": "Field may influence an identity, callback, redirect, URL, or token workflow; inspect application-side validation.",
                        })
                    if PRIVILEGE_NAME_RE.search(name):
                        identity_hints.append({
                            "source": "form field",
                            "name": name[:120],
                            "action": action,
                            "note": "Privilege-related field observed. This is not proof that the server trusts client-supplied privilege values.",
                        })
                    if token_like and value:
                        if getattr(self.config, "show_workflow_tokens", False):
                            self.log(f"Workflow token {name}: {value[:512]}", style="yellow")
                        else:
                            self.log(f"Workflow token detected: {name} (value withheld; length={len(value)})")

                record = {
                    "page": final_url,
                    "action": action,
                    "method": method,
                    "enctype": str(form.get("enctype") or "application/x-www-form-urlencoded"),
                    "fields": fields,
                }
                forms.append(record)
                runtime_forms.append({
                    "page": final_url,
                    "action": action,
                    "method": method,
                    "enctype": str(form.get("enctype") or "application/x-www-form-urlencoded").lower(),
                    "fields": runtime_fields,
                })
                if self.rm.is_same_origin(action):
                    self.reporter.add_endpoint(action)
                self.log(
                    f"Form #{form_index} on {final_url}: {method} {action} "
                    f"({len(fields)} named field(s))"
                )

            # Collect same-origin script references and extract endpoint strings.
            for script in soup.find_all("script", src=True):
                script_url = urljoin(final_url, str(script.get("src", "")))
                if self.rm.is_same_origin(script_url) and script_url not in seen_scripts:
                    seen_scripts.add(script_url)
                    if len(seen_scripts) >= MAX_SCRIPTS:
                        break
                    if not self._can_continue():
                        break
                    script_response = self.rm.get(script_url, allow_redirects=True)
                    if script_response is not None:
                        self._extract_js_references(
                            script_response.text or "", script_url, js_endpoints, identity_hints
                        )

            # Inline script URL and route strings.
            for script in soup.find_all("script"):
                if script.string:
                    self._extract_js_references(script.string, final_url, js_endpoints, identity_hints)

        for endpoint in sorted(js_endpoints):
            self.reporter.add_endpoint(endpoint)

        # Inspect the standard OIDC discovery document only on the target origin.
        discovery_url = urljoin(origin + "/", ".well-known/openid-configuration")
        if discovery_url not in seen_pages and self._can_continue():
            discovery = self.rm.get(discovery_url, allow_redirects=False)
            if discovery is not None and discovery.status_code == 200:
                self.reporter.add_endpoint(discovery_url)
                self._inspect_json(discovery.text or "", discovery_url, parameters, identity_hints)
                self.log("OpenID Connect discovery document found")

        self.reporter.runtime_context["forms"] = runtime_forms
        self.reporter.extra["workflow_analysis"] = {
            "pages_inspected": page_count,
            "forms": forms,
            "parameters": {k: sorted(set(v))[:10] for k, v in parameters.items()},
            "identity_hints": identity_hints[:100],
            "javascript_endpoints": sorted(js_endpoints),
            "proxy_headers": proxy_headers,
            "session_note": "The shared HTTP session retains same-origin cookies during this scan. Form submissions are not performed.",
        }

        self.log(f"Pages inspected: {page_count}; forms found: {len(forms)}")
        self.log(f"Interesting parameter names: {len(parameters)}; JS endpoints: {len(js_endpoints)}")

        if forms:
            token_fields = [
                field["name"]
                for form in forms
                for field in form["fields"]
                if TOKEN_NAME_RE.search(field["name"])
            ]
            if token_fields:
                detail = (
                    "Detected field names: "
                    + ", ".join(sorted(set(token_fields))[:20])
                    + ". Values are withheld from the report; the session cookie jar is retained in memory."
                )
                self.reporter.add_finding(
                    "Ticket / CSRF workflow fields identified",
                    severity="info",
                    detail=detail,
                    url=origin,
                    method="GET",
                    parameter=", ".join(sorted(set(token_fields))[:20]),
                    evidence_snippet=detail,
                )

        privilege_fields = sorted({
            hint["name"] for hint in identity_hints
            if hint.get("source") == "form field" and PRIVILEGE_NAME_RE.search(hint.get("name", ""))
        })
        if privilege_fields:
            detail = (
                "Fields: " + ", ".join(privilege_fields[:20])
                + ". Server-side authorization must be verified; no privilege values were modified."
            )
            self.reporter.add_finding(
                "Client-visible privilege fields observed",
                severity="info",
                detail=detail,
                url=origin,
                method="GET",
                parameter=", ".join(privilege_fields[:20]),
                evidence_snippet=detail,
            )

        url_fields = sorted({
            hint["name"] for hint in identity_hints
            if IDENTITY_NAME_RE.search(hint.get("name", ""))
        })
        if url_fields:
            detail = (
                "Fields: " + ", ".join(url_fields[:20])
                + ". Inspect validation and server-side fetch behavior manually; no internal addresses were contacted."
            )
            self.reporter.add_finding(
                "Identity / callback / URL input candidates",
                severity="info",
                detail=detail,
                url=origin,
                method="GET",
                parameter=", ".join(url_fields[:20]),
                evidence_snippet=detail,
            )

        if proxy_headers:
            detail = (
                "Response headers suggest one or more proxy/gateway layers: "
                + ", ".join(sorted(proxy_headers.keys()))
                + ". These are response-side clues only, not proof of CL.TE/TE.CL. Use Burp Repeater manually in an authorized lab; ProbeX does not send ambiguous framing requests."
            )
            self.reporter.add_finding(
                "HTTP intermediary indicators observed",
                severity="info",
                detail=detail,
                url=origin,
                method="GET",
                parameter="",
                evidence_snippet=", ".join(sorted(proxy_headers.keys())),
            )

    def _inspect_json(
        self,
        body: str,
        source_url: str,
        parameters: Dict[str, List[str]],
        identity_hints: List[Dict[str, str]],
    ) -> None:
        try:
            obj = json.loads(body)
        except (TypeError, ValueError):
            return

        def walk(value: Any, path: str = "") -> None:
            if isinstance(value, dict):
                for key, child in value.items():
                    key_s = str(key)
                    full = f"{path}.{key_s}" if path else key_s
                    parameters[key_s].append(source_url)
                    if IDENTITY_NAME_RE.search(key_s):
                        identity_hints.append({
                            "source": "JSON key",
                            "name": full[:160],
                            "action": source_url,
                            "note": "Identity, URL, callback, or token-related response key observed.",
                        })
                    child_text = str(child) if isinstance(child, (str, int, float)) else ""
                    if URL_VALUE_RE.match(child_text):
                        identity_hints.append({
                            "source": "JSON URL value",
                            "name": full[:160],
                            "action": source_url,
                            "note": f"URL-valued response field references {urlparse(child_text).hostname or 'an external host'}.",
                        })
                    walk(child, full)
            elif isinstance(value, list):
                for index, child in enumerate(value[:100]):
                    walk(child, f"{path}[{index}]")

        walk(obj)

    def _extract_js_references(
        self,
        source: str,
        source_url: str,
        endpoints: Set[str],
        identity_hints: List[Dict[str, str]],
    ) -> None:
        text = source[:MAX_BODY_CHARS]
        # Relative API paths and common well-known endpoints.
        for match in re.findall(r"['\"]((?:/|\\.\\./)[A-Za-z0-9_./?=&%{}-]{1,180})['\"]", text):
            candidate = urljoin(source_url, match)
            if self.rm.is_same_origin(candidate):
                endpoints.add(self._without_fragment(candidate))
        for match in re.findall(r"['\"](https?://[^'\"\\s]{1,240})['\"]", text, re.I):
            candidate = urljoin(source_url, match)
            if self.rm.is_same_origin(candidate):
                endpoints.add(self._without_fragment(candidate))
            elif IDENTITY_NAME_RE.search(match):
                identity_hints.append({
                    "source": "JavaScript URL string",
                    "name": "URL reference",
                    "action": source_url,
                    "note": f"External URL reference observed: {urlparse(match).hostname or 'unknown host'}; not contacted.",
                })

    @staticmethod
    def _without_fragment(url: str) -> str:
        parsed = urlparse(url)
        return parsed._replace(fragment="").geturl()

    @staticmethod
    def _safe_preview(value: str) -> str:
        value = re.sub(r"\s+", " ", value).strip()
        return value[:40]

    def _can_continue(self) -> bool:
        return self.config.can_request() and not self.rm.stopped_by_429
