#!/usr/bin/env python3
"""
JFrog Xray Vulnerability Report - Scripted Input for Splunk
============================================================
Reads JFrog Xray vulnerability report JSON files (exported from the
JFrog Platform UI or API) and emits one Splunk event per vulnerability row.

Expected JSON format:
{
  "total_rows": <int>,
  "rows": [
    {
      "cves": [{"cve": "CVE-...", "cvss_v3_score": 9.8, ...}],
      "cvss3_max_score": 9.8,
      "severity": "Critical",
      "component_physical_path": "...",
      "impact_path": ["docker://...", "..."],
      "fixed_versions": ["1.2.3"],
      "issue_id": "XRAY-...",
      "project_keys": ["proj1"],
      "applicability": true|false|null,
      "applicability_result": "applicable|not_applicable|...",
      "summary": "...",
      "vulnerable_component": "pypi://package:version",
      "impacted_artifact": "docker://repo/image:tag",
      "path": "repo/path/manifest.json",
      "published": "2026-01-21T17:17:32Z",
      "artifact_scan_time": "2026-02-02T07:57:20Z",
      "package_type": "pypi"
    },
    ...
  ]
}

Configuration (via inputs.conf or environment variables):
  JFROG_VULN_REPORT_DIR   - Directory to scan for report JSON files
                            (default: /tmp/jfrog_vuln_reports)
  JFROG_VULN_CHECKPOINT   - Path to the checkpoint file used to avoid
                            re-processing already ingested files
                            (default: <SPLUNK_DB>/jfrog_vuln_checkpoint.json)

Output:
  One JSON object per line to stdout. Splunk ingests these as individual
  events using sourcetype=jfrog:xray:vulnerability_report.
"""

import json
import os
import sys
import glob
import re
import hashlib
import logging
from datetime import datetime, timezone

# ---------------------------------------------------------------------------
# Logging — write to stderr so it shows up in Splunk's splunkd.log
# ---------------------------------------------------------------------------
logging.basicConfig(
    stream=sys.stderr,
    level=logging.INFO,
    format="%(asctime)s jfrog_vuln_report_input %(levelname)s %(message)s",
)
log = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------
REPORT_DIR = os.environ.get(
    "JFROG_VULN_REPORT_DIR",
    os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "sample_reports"),
)

_splunk_db = os.environ.get("SPLUNK_DB", "/tmp")
CHECKPOINT_FILE = os.environ.get(
    "JFROG_VULN_CHECKPOINT",
    os.path.join(_splunk_db, "jfrog_vuln_checkpoint.json"),
)

# Only pick up files whose names look like Xray vulnerability report exports.
# Matches patterns like:
#   Vulnerabilities_*_report_*.json
#   xray_vuln_report_*.json
#   *.json  (if you want to ingest all JSON files in the directory)
FILE_GLOB = "*.json"

# ---------------------------------------------------------------------------
# Checkpoint helpers — track files by (path, mtime, size) so we re-process
# if a file is replaced with updated content.
# ---------------------------------------------------------------------------

def _checkpoint_key(filepath: str) -> str:
    stat = os.stat(filepath)
    return f"{filepath}|{stat.st_mtime}|{stat.st_size}"


def load_checkpoint() -> dict:
    if os.path.exists(CHECKPOINT_FILE):
        try:
            with open(CHECKPOINT_FILE, "r", encoding="utf-8") as fh:
                return json.load(fh)
        except (json.JSONDecodeError, OSError) as exc:
            log.warning("Could not read checkpoint file %s: %s", CHECKPOINT_FILE, exc)
    return {}


def save_checkpoint(checkpoint: dict) -> None:
    os.makedirs(os.path.dirname(os.path.abspath(CHECKPOINT_FILE)), exist_ok=True)
    try:
        with open(CHECKPOINT_FILE, "w", encoding="utf-8") as fh:
            json.dump(checkpoint, fh, indent=2)
    except OSError as exc:
        log.error("Could not save checkpoint file %s: %s", CHECKPOINT_FILE, exc)


# ---------------------------------------------------------------------------
# Filename metadata parser
# Extracts the report generation date from the Xray export filename:
#   Vulnerabilities_<watch>_report_<DD>_<Mon>_<YYYY>_<HH>_<MM>__GMT<offset>-<D>-<M>-<YYYY>.json
# ---------------------------------------------------------------------------
_REPORT_DATE_RE = re.compile(
    r"(\d{1,2})_(\w{3})_(\d{4})_(\d{1,2})_(\d{2})",
    re.IGNORECASE,
)
_MONTH_MAP = {
    "jan": 1, "feb": 2, "mar": 3, "apr": 4,
    "may": 5, "jun": 6, "jul": 7, "aug": 8,
    "sep": 9, "oct": 10, "nov": 11, "dec": 12,
}


def _parse_report_date(filename: str) -> str:
    """Return ISO-8601 date string parsed from the report filename, or empty string."""
    m = _REPORT_DATE_RE.search(filename)
    if m:
        day, mon_str, year, hour, minute = m.groups()
        month = _MONTH_MAP.get(mon_str.lower())
        if month:
            try:
                dt = datetime(int(year), month, int(day), int(hour), int(minute),
                               tzinfo=timezone.utc)
                return dt.isoformat()
            except ValueError:
                pass
    return ""


# ---------------------------------------------------------------------------
# Event builder — flatten one row dict into a Splunk-friendly event
# ---------------------------------------------------------------------------

def build_event(row: dict, report_file: str, report_total_rows: int,
                report_generated: str) -> dict:
    """
    Flatten a single vulnerability row into a flat dict suitable for
    Splunk JSON ingestion.  Arrays are converted to multi-value strings
    so they work naturally with Splunk's MV field operators.
    """
    evt = {}

    # --- Report-level metadata ---
    evt["report_file"] = report_file
    evt["report_total_rows"] = report_total_rows
    if report_generated:
        evt["report_generated"] = report_generated

    # --- Primary timestamp: use artifact_scan_time for _time ---
    # Props.conf TIME_PREFIX will extract this as the Splunk event timestamp.
    scan_time = row.get("artifact_scan_time", "")
    evt["artifact_scan_time"] = scan_time

    # --- CVE details ---
    cves = row.get("cves") or []
    if cves:
        # Promote first / highest-score CVE to top-level fields
        primary = max(cves, key=lambda c: c.get("cvss_v3_score") or c.get("cvss_v2_score") or 0)
        evt["cve"]              = primary.get("cve", "")
        evt["cvss_v3_score"]    = primary.get("cvss_v3_score")
        evt["cvss_v3_vector"]   = primary.get("cvss_v3_vector", "")
        evt["cvss_v2_score"]    = primary.get("cvss_v2_score")
        evt["cvss_v2_vector"]   = primary.get("cvss_v2_vector", "")
        evt["cvss_v4_score"]    = primary.get("cvss_v4_score")
        evt["cvss_v4_vector"]   = primary.get("cvss_v4_vector", "")

        # Multi-value: all CVE IDs in case a row has multiple CVEs
        evt["cve_ids"] = [c.get("cve", "") for c in cves if c.get("cve")]

    # Remove None values from CVE numerics so they don't clutter the event
    for fld in ("cvss_v3_score", "cvss_v2_score", "cvss_v4_score",
                "cvss_v3_vector", "cvss_v2_vector", "cvss_v4_vector"):
        if evt.get(fld) is None:
            evt.pop(fld, None)

    # --- Scalar fields (pass through) ---
    scalar_fields = (
        "severity", "cvss3_max_score", "cvss2_max_score",
        "issue_id", "summary", "vulnerable_component",
        "impacted_artifact", "path", "published",
        "component_physical_path", "package_type",
        "applicability", "applicability_result",
    )
    for fld in scalar_fields:
        val = row.get(fld)
        if val is not None:
            evt[fld] = val

    # --- Array fields → multi-value strings ---
    # impact_path: hierarchy from top-level artifact down to the vulnerable package
    impact_path = row.get("impact_path") or []
    if impact_path:
        evt["impact_path"] = impact_path
        evt["impact_path_depth"] = len(impact_path)
        # Convenience field: the root artifact (first element)
        evt["root_artifact"] = impact_path[0] if impact_path else ""

    fixed_versions = row.get("fixed_versions") or []
    if fixed_versions:
        evt["fixed_versions"] = fixed_versions
        evt["fixed_versions_count"] = len(fixed_versions)

    project_keys = row.get("project_keys") or []
    if project_keys:
        evt["project_keys"] = project_keys

    # --- Derived convenience fields ---
    # Extract package name and version from vulnerable_component
    # e.g. "pypi://vllm:0.12.0" → package_name=vllm, package_version=0.12.0
    vc = evt.get("vulnerable_component", "")
    vc_match = re.match(r"[^:]+://(.+):([^:]+)$", vc)
    if vc_match:
        evt["package_name"]    = vc_match.group(1)
        evt["package_version"] = vc_match.group(2)

    # Extract artifact type from impacted_artifact scheme
    # e.g. "docker://..." → artifact_type=docker
    ia = evt.get("impacted_artifact", "")
    ia_scheme = re.match(r"(\w+)://", ia)
    if ia_scheme:
        evt["artifact_type"] = ia_scheme.group(1)

    # Severity numeric rank for easy sorting/alerting
    severity_rank = {
        "Critical": 4, "High": 3, "Medium": 2, "Low": 1, "Unknown": 0
    }
    evt["severity_rank"] = severity_rank.get(evt.get("severity", ""), 0)

    return evt


# ---------------------------------------------------------------------------
# File processor
# ---------------------------------------------------------------------------

def process_file(filepath: str) -> int:
    """
    Parse one report file and write events to stdout.
    Returns the number of events emitted.
    """
    report_file = os.path.basename(filepath)
    report_generated = _parse_report_date(report_file)
    emitted = 0

    log.info("Processing report file: %s", filepath)
    try:
        with open(filepath, "r", encoding="utf-8") as fh:
            data = json.load(fh)
    except (json.JSONDecodeError, OSError) as exc:
        log.error("Failed to parse %s: %s", filepath, exc)
        return 0

    rows = data.get("rows")
    if not isinstance(rows, list):
        log.warning("No 'rows' array found in %s — skipping", filepath)
        return 0

    total_rows = data.get("total_rows", len(rows))

    for row in rows:
        if not isinstance(row, dict):
            continue
        try:
            evt = build_event(row, report_file, total_rows, report_generated)
            # One JSON object per line → Splunk reads each line as one event
            sys.stdout.write(json.dumps(evt, default=str) + "\n")
            emitted += 1
        except Exception as exc:  # pylint: disable=broad-except
            log.error("Error building event from row in %s: %s", filepath, exc)

    sys.stdout.flush()
    log.info("Emitted %d events from %s", emitted, filepath)
    return emitted


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main() -> None:
    if not os.path.isdir(REPORT_DIR):
        log.warning(
            "Report directory does not exist: %s  (set JFROG_VULN_REPORT_DIR)", REPORT_DIR
        )
        sys.exit(0)

    checkpoint = load_checkpoint()
    updated = False

    report_files = sorted(glob.glob(os.path.join(REPORT_DIR, FILE_GLOB)))
    if not report_files:
        log.info("No report files found in %s matching '%s'", REPORT_DIR, FILE_GLOB)
        sys.exit(0)

    for filepath in report_files:
        key = _checkpoint_key(filepath)
        if checkpoint.get(filepath) == key:
            log.debug("Skipping already-processed file: %s", filepath)
            continue

        count = process_file(filepath)
        if count > 0:
            checkpoint[filepath] = key
            updated = True

    if updated:
        save_checkpoint(checkpoint)


if __name__ == "__main__":
    main()
