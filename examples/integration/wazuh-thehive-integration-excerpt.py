"""
Wazuh → TheHive integration — representative excerpt
Author: Abed el rahman Ismaiil

This file shows the core logic of a custom ~1,000-line integration script
that bridges Wazuh (SIEM/XDR) to TheHive (case management platform).

The full script handles three alert branches (Suricata network alerts,
Sysmon endpoint alerts, and a generic branch for SSH/PAM lateral movement),
two-level deduplication, MITRE ATT&CK tagging, and Cortex enrichment.

This excerpt illustrates:
  1. Two-level deduplication logic (grouping + per-signature rate-limiting)
  2. Observable creation with type validation
  3. MITRE ATT&CK procedure attachment

NOTE: secrets (API keys, URLs) are loaded from an external JSON file that
is excluded from version control (.gitignore). No credentials appear here.
"""

import json
import sys
import time
import logging
from datetime import datetime, timezone


# ---------------------------------------------------------------------------
# 1. TWO-LEVEL DEDUPLICATION
# ---------------------------------------------------------------------------
# Problem: a single attack campaign generates hundreds of similar alerts.
# Sending each as a separate TheHive case overwhelms analysts.
#
# Solution:
#   Level 1 — group alerts by source IP into a single case
#              (all alerts from the same attacker → one case)
#   Level 2 — within that case, limit duplicate comments per signature
#              to one per hour (prevents comment floods)
# ---------------------------------------------------------------------------

def get_or_create_case(state: dict, src_ip: str, title: str,
                       description: str, severity: int, tags: list) -> str:
    """
    Return the TheHive case ID for src_ip, creating one if none exists.
    State is persisted to disk so deduplication survives script restarts.
    """
    existing = state.get("cases_by_ip", {}).get(src_ip)

    if existing:
        case_id = existing["case_id"]
        log_message(f"Dedup level-1: reusing case {case_id} for {src_ip}")
        return case_id

    # No existing case for this IP — create one
    case_id = create_case(title, description, severity, tags)
    if not state.get("cases_by_ip"):
        state["cases_by_ip"] = {}
    state["cases_by_ip"][src_ip] = {
        "case_id": case_id,
        "first_seen": datetime.now(timezone.utc).isoformat(),
        "signatures": {}
    }
    save_state(state)
    return case_id


def should_add_comment(state: dict, src_ip: str,
                       signature: str) -> bool:
    """
    Level-2 dedup: return True only if this signature has not been
    commented in the last hour for this source IP.
    """
    cases = state.get("cases_by_ip", {})
    ip_data = cases.get(src_ip, {})
    sigs = ip_data.get("signatures", {})
    last_seen = sigs.get(signature, {}).get("last_seen")

    if not last_seen:
        return True  # first occurrence, always add

    delta = time.time() - last_seen
    return delta > 3600  # one comment per signature per hour


# ---------------------------------------------------------------------------
# 2. OBSERVABLE CREATION WITH TYPE VALIDATION
# ---------------------------------------------------------------------------
# An observable is data an analyst can pivot on or enrich: IP, URL, hash,
# filename. Protocol names, alert categories, and MITRE technique IDs are
# metadata — they belong in the case description or the TTPs tab, not as
# observables. Misclassifying them pollutes the observable list.
# ---------------------------------------------------------------------------

VALID_OBSERVABLE_TYPES = {"ip", "url", "hash", "filename", "domain", "other"}

def normalize_observable_value(value: str) -> str | None:
    """Strip whitespace and return None for empty or placeholder values."""
    if not value:
        return None
    value = str(value).strip()
    return value if value and value.lower() not in ("none", "null", "-", "") else None


def add_observable(case_id: str, data_type: str, data: str,
                   message: str, tags: list = None,
                   auto_enrich: bool = True) -> dict | None:
    """
    Create an observable in a TheHive case.

    Only meaningful, pivot-able data is added:
      - ip       → attacker/victim addresses
      - url      → HTTP URLs observed in network traffic
      - hash     → file hashes from Sysmon process events
      - filename → process images and parent processes
      - other    → command lines (may contain embedded IOCs)

    MITRE technique IDs, alert categories, and protocol names are NOT
    passed here — they are handled separately via add_mitre_procedures()
    and the case description.
    """
    data = normalize_observable_value(data)
    if not data:
        return None

    observable = {
        "dataType": data_type,
        "data": str(data),
        "message": message,
        "tlp": 2,   # AMBER — restricted to the organisation
        "pap": 2,   # AMBER — active response requires approval
        "ioc": False,
        "sighted": True,
        "tags": tags or [],
    }

    response = post_json(
        f"{THEHIVE_URL}/api/v1/case/{case_id}/observable",
        observable,
        THEHIVE_HEADERS,
    )
    return response


# ---------------------------------------------------------------------------
# 3. MITRE ATT&CK PROCEDURE ATTACHMENT
# ---------------------------------------------------------------------------
# TheHive has a dedicated TTPs tab for MITRE ATT&CK techniques.
# Using this tab (rather than creating observables for technique IDs)
# gives analysts the structured ATT&CK context they expect.
# ---------------------------------------------------------------------------

def add_mitre_procedures(case_id: str, pattern_ids: list,
                          tactics: list, techniques: list,
                          context: str = "") -> None:
    """
    Attach MITRE ATT&CK techniques to a case's TTPs tab.

    Each (pattern_id, tactic, technique) triple becomes one procedure,
    linked to the ATT&CK framework entry so analysts can navigate directly
    to the technique documentation.
    """
    for i, pattern_id in enumerate(pattern_ids):
        tactic    = tactics[i]    if i < len(tactics)    else ""
        technique = techniques[i] if i < len(techniques) else ""

        procedure = {
            "patternId":   pattern_id,   # e.g. "T1053.005"
            "tactic":      tactic,        # e.g. "Persistence"
            "description": technique,     # e.g. "Scheduled Task/Job"
            "occurDate":   int(time.time() * 1000),
            "context":     context,        # e.g. "Sysmon alert: rule 100321"
        }
        post_json(
            f"{THEHIVE_URL}/api/v1/case/{case_id}/procedure",
            procedure,
            THEHIVE_HEADERS,
        )


# ---------------------------------------------------------------------------
# EXAMPLE FLOW — Sysmon persistence alert (T1053.005)
# ---------------------------------------------------------------------------
# When Wazuh fires rule 100321 (schtasks /create /ru System):
#
#   1. Dedup level-1: find or create a case for this agent IP
#   2. Add the meaningful observables (agent IP, process image, command line)
#   3. Attach the MITRE TTP to the dedicated TTPs tab
#   4. Add a timestamped comment with the alert details
#
# Result: one TheHive case per endpoint (not one per alert), with clean
# observables and structured ATT&CK context ready for investigation.
# ---------------------------------------------------------------------------

def handle_sysmon_alert(alert: dict, state: dict) -> None:
    agent_ip       = alert.get("agent", {}).get("ip")
    rule_id        = alert.get("rule", {}).get("id")
    rule_desc      = alert.get("rule", {}).get("description", "")
    mitre_ids      = alert.get("rule", {}).get("mitre", {}).get("id", [])
    mitre_tactics  = alert.get("rule", {}).get("mitre", {}).get("tactic", [])
    mitre_techs    = alert.get("rule", {}).get("mitre", {}).get("technique", [])

    event_data     = alert.get("data", {}).get("win", {}).get("eventdata", {})
    process_image  = event_data.get("image")
    parent_image   = event_data.get("parentImage")
    command_line   = event_data.get("commandLine")
    hashes         = event_data.get("hashes", "").split(",")

    # Level-1 dedup: one case per agent
    case_id = get_or_create_case(
        state, src_ip=agent_ip,
        title=f"Sysmon endpoint behavior: {rule_desc}",
        description=f"Rule {rule_id} fired on agent {agent_ip}.\n\n{rule_desc}",
        severity=3 if int(alert.get("rule", {}).get("level", 0)) >= 12 else 2,
        tags=["wazuh", "sysmon", "auto-case"],
    )

    # Add pivot-able observables only
    add_observable(case_id, "ip",       agent_ip,     "Wazuh agent IP",          ["agent"])
    add_observable(case_id, "filename", process_image, "Sysmon process image",    ["process"])
    add_observable(case_id, "filename", parent_image,  "Sysmon parent process",   ["parent"])
    add_observable(case_id, "other",    command_line,  "Sysmon command line",     ["command_line"])

    for h in hashes:
        clean = h.split("=")[-1].strip() if "=" in h else h.strip()
        add_observable(case_id, "hash", clean, "Hash from Sysmon event", ["hash"])

    # MITRE ATT&CK → dedicated TTPs tab (NOT as observables)
    if mitre_ids:
        add_mitre_procedures(
            case_id,
            pattern_ids=mitre_ids,
            tactics=mitre_tactics,
            techniques=mitre_techs,
            context=f"Sysmon alert: {rule_desc}",
        )
