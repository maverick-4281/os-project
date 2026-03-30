"""
Module 3: Threat Detection
OS Concepts:
Buffer overflow detection simulates OS memory protection mechanisms:
stack canaries (GCC -fstack-protector), ASLR, and NX bits.
Malware detection mirrors signature-based AV scanners at OS level
similar to Linux Security Modules (LSM) and Windows Kernel Patch Protection.
"""

import hashlib
import json
import os
import re
import secrets
from datetime import datetime
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent
LOGS_DIR = BASE_DIR / "data" / "logs"
FILES_DIR = BASE_DIR / "data" / "files"

MALWARE_SIGNATURES = {
    "eicar_test":             r"X5O!P%@AP",
    "reverse_shell":          r"(bash -i|nc -e|/bin/sh)",
    "keylogger":              r"(GetAsyncKeyState|SetWindowsHookEx|keylog)",
    "ransomware":             r"(\.encrypt\(|CryptEncrypt|ransom)",
    "rootkit":                r"(hide_process|LD_PRELOAD|/proc/\d+/mem)",
    "trojan_dropper":         r"(urllib\.request\.urlretrieve|wget http|curl http.*\|.*sh)",
    "privilege_escalation":   r"(sudo chmod 777|chmod \+s|setuid\(0\))",
    "data_exfiltration":      r"(base64\.b64encode.*socket|ftplib\.FTP)",
}

SEVERITY_MAP = {
    "eicar_test":           "high",
    "reverse_shell":        "high",
    "keylogger":            "high",
    "ransomware":           "high",
    "rootkit":              "high",
    "trojan_dropper":       "medium",
    "privilege_escalation": "medium",
    "data_exfiltration":    "medium",
}


def check_buffer_overflow(input_string: str, max_length: int = 256) -> dict:
    encoded = input_string.encode("utf-8")
    length = len(encoded)
    detected = False
    reason = []
    severity = "low"

    if length > max_length:
        detected = True
        reason.append(f"Input length {length} exceeds max {max_length}")
        severity = "high"

    if re.search(r"(.)\1{99,}", input_string):
        detected = True
        reason.append("Repeated character pattern detected (possible NOP sled)")
        severity = "high"

    if "\x00" in input_string:
        detected = True
        reason.append("Null byte detected")
        severity = "high"

    if re.search(r"%[sxnd]", input_string):
        detected = True
        reason.append("Format string pattern detected (%s, %x, %n, %d)")
        severity = "medium" if severity == "low" else severity

    if re.search(r"[;|&><`]", input_string):
        detected = True
        reason.append("Shell metacharacter detected (; | & > < `)")
        severity = "medium" if severity == "low" else severity

    return {
        "detected": detected,
        "reason": "; ".join(reason) if reason else "No overflow detected",
        "severity": severity if detected else "none",
        "length": length,
        "max_length": max_length,
    }


def simulate_stack_canary(data: str) -> dict:
    canary = secrets.token_hex(8)
    overflow = check_buffer_overflow(data)
    canary_intact = not overflow["detected"]
    return {
        "canary_value": canary,
        "canary_intact": canary_intact,
        "message": "Stack canary intact." if canary_intact else "Stack canary corrupted! Overflow detected.",
    }


def analyze_input_safety(input_string: str) -> dict:
    overflow = check_buffer_overflow(input_string)
    canary = simulate_stack_canary(input_string)
    findings = []

    if overflow["detected"]:
        findings.append({
            "type": "buffer_overflow",
            "detail": overflow["reason"],
            "severity": overflow["severity"]
        })

    sql_keywords = r"(SELECT|DROP|INSERT|UPDATE|DELETE|--|;|\bOR\b|\bAND\b)"
    if re.search(sql_keywords, input_string, re.IGNORECASE):
        findings.append({
            "type": "sql_injection",
            "detail": "SQL keyword or operator detected",
            "severity": "high"
        })

    if re.search(r"(\.\./|\.\.\\|/etc/|C:\\\\)", input_string):
        findings.append({
            "type": "path_traversal",
            "detail": "Path traversal pattern detected",
            "severity": "high"
        })

    if re.search(r"(<script|javascript:|onerror=)", input_string, re.IGNORECASE):
        findings.append({
            "type": "xss",
            "detail": "XSS pattern detected",
            "severity": "high"
        })

    threat_level = "CLEAN"
    if findings:
        severities = [f["severity"] for f in findings]
        if "high" in severities:
            threat_level = "HIGH"
        elif "medium" in severities:
            threat_level = "MEDIUM"
        else:
            threat_level = "LOW"

    return {
        "input_length": len(input_string),
        "overflow": overflow,
        "canary": canary,
        "findings": findings,
        "threat_level": threat_level,
    }


def _match_signatures(content: str) -> list:
    threats = []
    lines = content.splitlines()
    for name, pattern in MALWARE_SIGNATURES.items():
        for i, line in enumerate(lines, start=1):
            if re.search(pattern, line, re.IGNORECASE):
                threats.append({
                    "name": name,
                    "pattern_matched": pattern,
                    "line_number": i,
                    "severity": SEVERITY_MAP.get(name, "low"),
                })
                break
    return threats


def scan_file_for_malware(filepath: str) -> dict:
    path = Path(filepath)
    if not path.exists():
        return {"error": "File not found"}

    with open(path, "rb") as f:
        raw = f.read()

    file_hash = hashlib.sha256(raw).hexdigest()
    try:
        content = raw.decode("utf-8", errors="replace")
    except Exception:
        content = ""

    threats = _match_signatures(content)
    return {
        "file": path.name,
        "hash": file_hash,
        "threats_found": threats,
        "scan_time": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "status": "INFECTED" if threats else "CLEAN",
    }


def scan_content_for_malware(content: str, source_label: str = "user_input") -> dict:
    content_hash = hashlib.sha256(content.encode("utf-8")).hexdigest()
    threats = _match_signatures(content)
    return {
        "file": source_label,
        "hash": content_hash,
        "threats_found": threats,
        "scan_time": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "status": "INFECTED" if threats else "CLEAN",
    }


def get_threat_level(scan_report: dict) -> str:
    threats = scan_report.get("threats_found", [])
    if not threats:
        return "CLEAN"
    severities = [t["severity"] for t in threats]
    if "high" in severities:
        return "CRITICAL"
    if "medium" in severities:
        return "HIGH"
    return "MEDIUM"


def log_threat(username: str, threat_report: dict) -> None:
    LOGS_DIR.mkdir(parents=True, exist_ok=True)
    threat_log = LOGS_DIR / "threats.log"
    entry = {
        "username": username,
        "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "report": threat_report,
    }
    with open(threat_log, "a") as f:
        f.write(json.dumps(entry) + "\n")