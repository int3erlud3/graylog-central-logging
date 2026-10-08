#!/usr/bin/env python3
"""Validate the provisioning JSON definitions (structure, references and security policy).

Usage: scripts/validate-definitions.py [DEFINITIONS_DIR]   (default: provisioning/)
Exit codes: 0 valid, 1 invalid, 2 unreadable or not JSON.
"""

from __future__ import annotations

import json
import re
import sys
from pathlib import Path

INPUT_TYPES = {
    "org.graylog2.inputs.syslog.tcp.SyslogTCPInput": "tcp",
    "org.graylog2.inputs.syslog.udp.SyslogUDPInput": "udp",
    "org.graylog2.inputs.gelf.tcp.GELFTCPInput": "tcp",
    "org.graylog2.inputs.gelf.udp.GELFUDPInput": "udp",
}
RULE_TYPES = set(range(1, 9))
OPERATORS = {">", ">=", "<", "<=", "=="}
RULE_TITLE = re.compile(r'^rule "([^"]+)"\s*$', re.MULTILINE)


def load(path: Path) -> dict:
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        print(f"error: {path}: {exc}", file=sys.stderr)
        sys.exit(2)
    if not isinstance(data, dict):
        print(f"error: {path}: top level must be an object", file=sys.stderr)
        sys.exit(2)
    return data


def unique_titles(items: list, kind: str, errors: list[str]) -> set[str]:
    seen: set[str] = set()
    for item in items:
        title = item.get("title") if isinstance(item, dict) else None
        if not isinstance(title, str) or not title.strip():
            errors.append(f"{kind}: every entry needs a non-empty title")
            continue
        if title in seen:
            errors.append(f"{kind}: duplicate title {title!r}")
        seen.add(title)
    return seen


def check_inputs(data: dict, errors: list[str]) -> None:
    inputs = data.get("inputs", [])
    unique_titles(inputs, "inputs", errors)
    bound: set[tuple[int, str]] = set()
    for inp in inputs:
        title = inp.get("title")
        proto = INPUT_TYPES.get(inp.get("type", ""))
        if proto is None:
            errors.append(f"input {title!r}: unknown type {inp.get('type')!r}")
            continue
        cfg = inp.get("configuration", {})
        port = cfg.get("port")
        if not isinstance(port, int) or not 1024 <= port <= 65535:
            errors.append(f"input {title!r}: port must be an integer 1024-65535 (graylog runs unprivileged)")
            continue
        if (port, proto) in bound:
            errors.append(f"input {title!r}: {port}/{proto} is already used by another input")
        bound.add((port, proto))
        if proto == "tcp":
            if cfg.get("tls_enable") is not True:
                errors.append(f"input {title!r}: TCP inputs must enable TLS (policy)")
            for key in ("tls_cert_file", "tls_key_file"):
                if not str(cfg.get(key, "")).startswith("/usr/share/graylog/certs/"):
                    errors.append(f"input {title!r}: {key} must point into /usr/share/graylog/certs/")


def check_streams(data: dict, errors: list[str]) -> set[str]:
    streams = data.get("streams", [])
    titles = unique_titles(streams, "streams", errors)
    for s in streams:
        title = s.get("title")
        if s.get("matching_type") not in {"AND", "OR"}:
            errors.append(f"stream {title!r}: matching_type must be AND or OR")
        rules = s.get("rules")
        if not isinstance(rules, list) or not rules:
            errors.append(f"stream {title!r}: needs at least one rule")
            continue
        for r in rules:
            if r.get("type") not in RULE_TYPES or not r.get("field"):
                errors.append(f"stream {title!r}: invalid rule {r!r}")
            if r.get("type") == 2:
                try:
                    re.compile(str(r.get("value", "")))
                except re.error as exc:
                    errors.append(f"stream {title!r}: invalid regex {r.get('value')!r}: {exc}")
    return titles


def check_pipelines(data: dict, base: Path, streams: set[str], errors: list[str]) -> None:
    pipelines = data.get("pipelines", [])
    unique_titles(pipelines, "pipelines", errors)
    rule_titles: dict[str, str] = {}
    for p in pipelines:
        for rf in p.get("rules", []):
            path = base / "pipelines" / rf
            if not path.is_file():
                errors.append(f"pipeline {p.get('title')!r}: missing rule file pipelines/{rf}")
                continue
            text = path.read_text(encoding="utf-8")
            m = RULE_TITLE.search(text)
            if (
                not m
                or not re.search(r"^\s*when\b", text, re.M)
                or not re.search(r"^\s*then\b", text, re.M)
                or not re.search(r"^\s*end\s*$", text, re.M)
            ):
                errors.append(f"pipelines/{rf}: expected 'rule \"...\"', 'when', 'then' and 'end'")
                continue
            if m.group(1) in rule_titles and rule_titles[m.group(1)] != rf:
                errors.append(f"pipelines/{rf}: rule title {m.group(1)!r} also used in {rule_titles[m.group(1)]}")
            rule_titles[m.group(1)] = rf
        for st in p.get("streams", []):
            if st not in streams:
                errors.append(f"pipeline {p.get('title')!r}: unknown stream {st!r}")


def check_events(data: dict, streams: set[str], errors: list[str]) -> None:
    events = data.get("event_definitions", [])
    unique_titles(events, "event_definitions", errors)
    for e in events:
        title = e.get("title")
        if e.get("priority") not in {1, 2, 3}:
            errors.append(f"event {title!r}: priority must be 1, 2 or 3")
        if not isinstance(e.get("alert"), bool):
            errors.append(f"event {title!r}: alert must be true or false")
        if not isinstance(e.get("query"), str) or not e["query"].strip():
            errors.append(f"event {title!r}: query must be a non-empty string")
        refs = e.get("streams")
        if not isinstance(refs, list) or not refs:
            errors.append(f"event {title!r}: needs at least one stream")
        else:
            errors.extend(f"event {title!r}: unknown stream {s!r}" for s in refs if s not in streams)
        if not isinstance(e.get("group_by"), list):
            errors.append(f"event {title!r}: group_by must be a list")
        th = e.get("threshold")
        if th is not None and (
            not isinstance(th, dict)
            or th.get("type") != "count"
            or th.get("operator") not in OPERATORS
            or not isinstance(th.get("value"), (int, float))
        ):
            errors.append(f"event {title!r}: threshold must be null or {{type: count, operator, value}}")
        within, every = e.get("search_within_minutes"), e.get("execute_every_minutes")
        if not (isinstance(within, int) and isinstance(every, int) and 0 < every <= within <= 1440):
            errors.append(f"event {title!r}: need 0 < execute_every_minutes <= search_within_minutes <= 1440")


def main(argv: list[str]) -> int:
    base = Path(argv[1]) if len(argv) > 1 else Path(__file__).resolve().parent.parent / "provisioning"
    errors: list[str] = []
    check_inputs(load(base / "inputs.json"), errors)
    streams = check_streams(load(base / "streams.json"), errors)
    check_pipelines(load(base / "pipelines.json"), base, streams, errors)
    check_events(load(base / "event-definitions.json"), streams, errors)
    for err in errors:
        print(f"invalid: {err}", file=sys.stderr)
    if errors:
        return 1
    print(f"definitions OK: {base}")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
