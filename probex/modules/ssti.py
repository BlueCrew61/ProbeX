"""Low-impact Server-Side Template Injection (SSTI) detection.

This module performs bounded arithmetic-expression checks only. It does not
attempt file reads, command execution, sandbox escapes, or other post-detection
exploitation. It supports discovered same-origin GET/POST HTML forms and
existing same-origin query parameters.
"""

from __future__ import annotations

import re
import html
from typing import Any, Dict, List, Optional, Set, Tuple
from urllib.parse import parse_qsl, urlencode, urljoin, urlparse, urlunparse

from bs4 import BeautifulSoup

from .base import BaseModule


# Each expression has a distinct result so a stale/static response is less
# likely to be mistaken for evaluation. Prefix/suffix markers prove that the
# expression was evaluated in the submitted value.
PROBES: Tuple[Tuple[str, str, str], ...] = (
    ("{{7*7}}", "49", "Jinja2 / Twig / Nunjucks-style"),
    ("${8*9}", "72", "Freemarker / Velocity-style"),
    ("<%=11*7%>", "77", "ERB / EJS-style"),
    ("#{6*8}", "48", "Ruby / Java expression-style"),
    ("*{9*9}", "81", "Spring expression-style"),
)

MAX_DISCOVERY_PAGES = 5
MAX_FORMS = 8
MAX_FIELDS_PER_FORM = 8
MAX_CANDIDATES = 10
MAX_TEST_REQUESTS = 30
MAX_FILTER_DIAGNOSTIC_REQUESTS = 4
MAX_PAGE_CHARS = 250_000
CANDIDATE_NAME_RE = re.compile(
    r"template|content|message|comment|html|text|input|search|query|name|title|body|preview|render|view|subject",
    re.I,
)


class SSTIDetection(BaseModule):
    name = "SSTI Detection"

    def run(self) -> None:
        forms = self._runtime_forms()
        query_targets: List[Dict[str, Any]] = []

        # FlowAnalysis may already have collected form controls and retained
        # the shared session. When SSTI is selected on its own, discover a
        # small number of same-origin pages/forms here instead.
        if not forms:
            discovered_forms, discovered_queries = self._discover_inputs()
            forms.extend(discovered_forms)
            query_targets.extend(discovered_queries)
        else:
            query_targets.extend(self._runtime_query_targets())

        # Also inspect the base URL itself if it already contains parameters.
        base_query = self._query_target(self.config.base_url)
        if base_query:
            query_targets.append(base_query)

        # Deduplicate forms and query targets without exposing values in logs.
        forms = self._dedupe_forms(forms)[:MAX_FORMS]
        query_targets = self._dedupe_query_targets(query_targets)

        candidates: List[Tuple[str, Dict[str, Any], str]] = []
        for form in forms:
            action = form.get("action", "")
            method = str(form.get("method", "GET")).upper()
            if method not in ("GET", "POST") or not self.rm.is_same_origin(action):
                continue
            enctype = str(form.get("enctype", "application/x-www-form-urlencoded")).lower()
            if "multipart/form-data" in enctype or "application/json" in enctype:
                continue

            fields = form.get("fields", [])
            for field in self._ordered_candidate_fields(fields):
                candidates.append(("form", form, field["name"]))

        for target in query_targets:
            for name in target.get("candidate_names", []):
                candidates.append(("query", target, name))

        # Stable prioritization: form parameters are usually the meaningful
        # user-controlled input in CTF SSTI tasks; likely names come first.
        candidates = candidates[:MAX_CANDIDATES]
        if not candidates:
            self.log("No eligible same-origin text fields or query parameters found for SSTI checks")
            return

        self.log(
            f"Testing {len(candidates)} input candidate(s) with bounded arithmetic probes; "
            "no file-read or command-execution payloads are used"
        )

        requests_used = 0
        detected = False
        confirmed_candidate: Optional[Tuple[str, Dict[str, Any], str]] = None
        for kind, target, field_name in candidates:
            if detected or requests_used >= MAX_TEST_REQUESTS or not self.config.can_request():
                break

            for expression, expected, engine_hint in PROBES:
                if requests_used >= MAX_TEST_REQUESTS or not self.config.can_request():
                    break

                marker = "WSCBEGIN"
                ending = "WSCEND"
                submitted_value = f"{marker}{expression}{ending}"
                response = self._submit_probe(kind, target, field_name, submitted_value)
                if response is None:
                    # A failed request is still budgeted by RequestManager.
                    requests_used += 1
                    continue
                requests_used += 1
                body = response.text or ""
                expected_output = f"{marker}{expected}{ending}"

                if expected_output in body:
                    location = target.get("action") or target.get("url") or self.config.base_url
                    self.log(
                        f"Template expression evaluated in parameter '{field_name}' at {location} "
                        f"({engine_hint}; {expression} → {expected})",
                        style="yellow",
                    )
                    self.reporter.add_finding(
                        "SSTI: arithmetic expression evaluated",
                        severity="medium",
                        detail=(
                            f"A harmless template arithmetic expression was evaluated in field "
                            f"'{field_name}' using {kind.upper()} at {location}. Engine family hint: "
                            f"{engine_hint}. This confirms server-side expression evaluation, "
                            "but does not by itself establish file access or code execution."
                        ),
                        evidence=f"submitted={submitted_value}; observed={expected_output}",
                        url=location,
                        method=str(target.get("method", "GET")).upper() if kind == "form" else "GET",
                        parameter=field_name,
                        evidence_snippet=f"submitted={submitted_value}; observed={expected_output}",
                    )
                    self.reporter.extra.setdefault("ssti", []).append({
                        "location": location,
                        "method": str(target.get("method", "GET")).upper() if kind == "form" else "GET",
                        "parameter": field_name,
                        "probe_family": engine_hint,
                        "expression": expression,
                        "expected_output": expected_output,
                        "status_code": response.status_code,
                    })
                    detected = True
                    confirmed_candidate = (kind, target, field_name)
                    break

        if not detected:
            if requests_used == 0:
                self.log("SSTI checks skipped: no request budget remained")
            else:
                self.log(
                    f"No arithmetic SSTI evaluation confirmed across {len(candidates)} candidate(s) "
                    f"({requests_used} probe request(s))"
                )

        # A failed arithmetic test does not prove that a field is safe. Run a
        # small, inert reflection/normalization check against one representative
        # field. This reports only broad character classes; it does not derive
        # bypasses or suggest alternate payload encodings.
        diagnostic_candidate = confirmed_candidate or (candidates[0] if candidates else None)
        if diagnostic_candidate and self.config.can_request():
            self._diagnose_input_filtering(*diagnostic_candidate)

    def _diagnose_input_filtering(
        self,
        kind: str,
        target: Dict[str, Any],
        field_name: str,
    ) -> None:
        probes = [
            ("alphanumeric baseline", "WSCALPHAZ9182"),
            ("separator punctuation", "WSCSEP-A_B.C:D/E"),
            ("template delimiters", "WSCDLM-[A](B){C}<D>"),
            ("quotation marks", 'WSCQUOTE-\'A\'\\"B\\"'),
        ][:MAX_FILTER_DIAGNOSTIC_REQUESTS]
        observations: Dict[str, str] = {}
        baseline_seen = False

        for label, marker in probes:
            if not self.config.can_request():
                break
            response = self._submit_probe(kind, target, field_name, marker)
            if response is None:
                observations[label] = "request_failed_or_budget_stopped"
                continue
            body = response.text or ""
            visible = marker in body or marker in html.unescape(body)
            observations[label] = "preserved" if visible else "changed_or_not_reflected"
            if label == "alphanumeric baseline":
                baseline_seen = visible

        if not observations:
            return

        if not baseline_seen:
            self.log(
                "Input-filter behavior is inconclusive: the alphanumeric marker was not "
                "visible in the immediate response. The field may not be reflected, or "
                "the application may process it asynchronously.",
                style="yellow",
            )
            self.reporter.extra.setdefault("ssti_filter_diagnostics", []).append({
                "location": target.get("action") or target.get("url") or self.config.base_url,
                "parameter": field_name,
                "result": "inconclusive_no_baseline_reflection",
                "observations": observations,
            })
            return

        changed_groups = [
            label for label, result in observations.items()
            if label != "alphanumeric baseline" and result == "changed_or_not_reflected"
        ]
        self.log("Input transformation check (broad categories only):")
        for label, result in observations.items():
            self.log(f"{label}: {result}")

        result = "possible_character_class_filtering" if changed_groups else "tested_groups_preserved"
        self.reporter.extra.setdefault("ssti_filter_diagnostics", []).append({
            "location": target.get("action") or target.get("url") or self.config.base_url,
            "parameter": field_name,
            "result": result,
            "changed_groups": changed_groups,
            "observations": observations,
            "note": "A changed marker can also mean the field is not reflected in the response; this is not proof of a blacklist.",
        })
        if changed_groups:
            self.reporter.add_finding(
                "SSTI input transformation observed",
                severity="info",
                detail=(
                    f"The field '{field_name}' reflected an alphanumeric control marker, "
                    f"but one or more broad punctuation groups were not reflected unchanged. "
                    "This may indicate input normalization, output encoding, validation, or "
                    "context-dependent rendering; it does not prove a blacklist and no bypass "
                    "attempt was made."
                ),
                evidence="Changed groups: " + ", ".join(changed_groups),
                url=target.get("action") or target.get("url") or self.config.base_url,
                method="GET",
                parameter=field_name,
                evidence_snippet="Changed groups: " + ", ".join(changed_groups),
            )

    def _runtime_forms(self) -> List[Dict[str, Any]]:
        forms = self.reporter.runtime_context.get("forms", [])
        return [f for f in forms if isinstance(f, dict)] if isinstance(forms, list) else []

    def _runtime_query_targets(self) -> List[Dict[str, Any]]:
        targets: List[Dict[str, Any]] = []
        for endpoint in self.reporter.endpoints:
            target = self._query_target(endpoint)
            if target:
                targets.append(target)
        return targets

    def _query_target(self, url: str) -> Optional[Dict[str, Any]]:
        try:
            parsed = urlparse(url)
            pairs = parse_qsl(parsed.query, keep_blank_values=True)
            names = list(dict.fromkeys(name for name, _ in pairs if name))
            if not pairs or not names or not self.rm.is_same_origin(url):
                return None
            return {
                "url": url,
                "pairs": pairs,
                "candidate_names": names,
            }
        except (TypeError, ValueError):
            return None

    def _discover_inputs(self) -> Tuple[List[Dict[str, Any]], List[Dict[str, Any]]]:
        queue = [self.config.base_url.rstrip("/") + "/"]
        seen: Set[str] = set()
        forms: List[Dict[str, Any]] = []
        query_targets: List[Dict[str, Any]] = []
        pages = 0

        self.log("No prior form inventory found; doing limited same-origin form discovery")
        while queue and pages < MAX_DISCOVERY_PAGES and self.config.can_request():
            page_url = queue.pop(0)
            if page_url in seen or not self.rm.is_same_origin(page_url):
                continue
            seen.add(page_url)
            page_query = self._query_target(page_url)
            if page_query:
                query_targets.append(page_query)

            response = self.rm.get(page_url, allow_redirects=True)
            if response is None:
                continue
            pages += 1
            final_url = response.url or page_url
            if not self.rm.is_same_origin(final_url):
                continue
            body = (response.text or "")[:MAX_PAGE_CHARS]
            content_type = response.headers.get("Content-Type", "").lower()
            if "html" not in content_type and "<form" not in body.lower() and "<a " not in body.lower():
                continue

            soup = BeautifulSoup(body, "html.parser")
            for anchor in soup.find_all("a", href=True):
                candidate = urljoin(final_url, str(anchor.get("href", "")).strip())
                if not self.rm.is_same_origin(candidate):
                    continue
                candidate = candidate.split("#", 1)[0]
                if candidate not in seen and candidate not in queue and len(queue) < MAX_DISCOVERY_PAGES:
                    queue.append(candidate)
                query_target = self._query_target(candidate)
                if query_target:
                    query_targets.append(query_target)

            for form in soup.find_all("form"):
                action = urljoin(final_url, str(form.get("action") or final_url))
                if not self.rm.is_same_origin(action):
                    continue
                method = str(form.get("method") or "GET").upper()
                enctype = str(form.get("enctype") or "application/x-www-form-urlencoded").lower()
                fields: List[Dict[str, Any]] = []
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
                        if selected:
                            value = str(selected.get("value") if selected.has_attr("value") else selected.get_text(strip=True))
                    fields.append({
                        "name": name,
                        "type": kind,
                        "value": value,
                        "hidden": kind == "hidden",
                        "sensitive": bool(re.search(r"password|secret|api[_-]?key|authorization", name, re.I)) or kind == "password",
                        "required": control.has_attr("required"),
                    })
                forms.append({
                    "page": final_url,
                    "action": action,
                    "method": method,
                    "enctype": enctype,
                    "fields": fields,
                })
                if len(forms) >= MAX_FORMS:
                    break
            if len(forms) >= MAX_FORMS:
                break

        self.log(f"SSTI discovery inspected {pages} page(s), found {len(forms)} form(s)")
        return forms, query_targets

    def _ordered_candidate_fields(self, fields: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        candidates = []
        for field in fields:
            name = str(field.get("name") or "").strip()
            kind = str(field.get("type") or "text").lower()
            if not name or field.get("hidden") or field.get("sensitive"):
                continue
            if kind in ("password", "file", "submit", "button", "reset", "checkbox", "radio", "image"):
                continue
            candidates.append(field)
        candidates.sort(key=lambda f: (0 if CANDIDATE_NAME_RE.search(str(f.get("name", ""))) else 1, str(f.get("name", "")).lower()))
        return candidates[:MAX_FIELDS_PER_FORM]

    def _submit_probe(
        self,
        kind: str,
        target: Dict[str, Any],
        field_name: str,
        submitted_value: str,
    ):
        if kind == "query":
            pairs = list(target.get("pairs", []))
            replaced = False
            updated = []
            for name, value in pairs:
                if name == field_name and not replaced:
                    updated.append((name, submitted_value))
                    replaced = True
                else:
                    updated.append((name, value))
            if not replaced:
                updated.append((field_name, submitted_value))
            return self.rm.get(target["url"].split("#", 1)[0].split("?", 1)[0], params=updated)

        fields = target.get("fields", [])
        data = []
        replaced = False
        for field in fields:
            name = str(field.get("name") or "")
            value = str(field.get("value") or "")
            if name == field_name and not replaced:
                value = submitted_value
                replaced = True
            # Preserve hidden CSRF/ticket fields, but never log their values.
            data.append((name, value))
        if not replaced:
            data.append((field_name, submitted_value))

        headers = {"Referer": str(target.get("page") or self.config.base_url)}
        if str(target.get("method", "GET")).upper() == "POST":
            return self.rm.post(target["action"], data=data, headers=headers, allow_redirects=True)
        return self.rm.get(target["action"], params=data, headers=headers, allow_redirects=True)

    def _dedupe_forms(self, forms: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        seen = set()
        output = []
        for form in forms:
            key = (
                str(form.get("method", "GET")).upper(),
                str(form.get("action", "")),
                tuple(str(f.get("name", "")) for f in form.get("fields", [])),
            )
            if key in seen:
                continue
            seen.add(key)
            output.append(form)
        return output

    def _dedupe_query_targets(self, targets: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        seen = set()
        output = []
        for target in targets:
            key = (target.get("url"), tuple(target.get("candidate_names", [])))
            if key in seen:
                continue
            seen.add(key)
            output.append(target)
        return output
