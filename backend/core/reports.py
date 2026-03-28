"""Report generation functions — extracted from app.py."""

import re
import logging
from datetime import datetime
from typing import Dict

from .api_client import APIClient


def generate_text_report(analysis_results: str, base_filename: str = "security_analysis_report") -> tuple:
    """Generate a text report content without saving to file."""
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    filename = f"{base_filename}_{timestamp}.txt"
    report_content = f"""==============================================
CodeGuardianAI Security Analysis Report
Generated on: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
==============================================

{analysis_results}
"""
    return report_content, filename


def extract_vulnerabilities(analysis_text: str) -> list:
    """Extracts individual vulnerabilities from the analysis text."""
    vulnerability_pattern = re.compile(
        r"##\s*\[(Critical|High|Medium|Low)\]\s*Vulnerability\s*#(\d+):\s*([^\n]+)",
        re.IGNORECASE,
    )
    vulnerability_matches = list(vulnerability_pattern.finditer(analysis_text))

    emoji_map = {"critical": "🔴", "high": "🟠", "medium": "🟡", "low": "🟢"}
    severity_canon = {"critical": "Critical", "high": "High", "medium": "Medium", "low": "Low"}

    vulnerabilities = []
    for i, match in enumerate(vulnerability_matches):
        sev_raw, number, vuln_type = match.groups()
        severity = severity_canon.get(sev_raw.lower(), sev_raw.capitalize())
        emoji = emoji_map.get(sev_raw.lower(), "")

        segment = analysis_text[match.end():]

        location_match = re.search(
            r"\*\*Location:\*\*\s*(?:Lines?\s*~?)?([\d\-,]+)",
            segment,
            re.IGNORECASE,
        )
        location = location_match.group(1) if location_match else "Unknown"

        snippet_match = re.search(
            r"\*\*Code Snippet:\*\*\s*```[^\n]*\n(.*?)```",
            segment,
            re.DOTALL,
        )
        code_snippet = snippet_match.group(1).strip() if snippet_match else ""

        end_pos = vulnerability_matches[i + 1].start() if i + 1 < len(vulnerability_matches) else len(analysis_text)

        vulnerabilities.append({
            "emoji": emoji,
            "severity": severity,
            "number": number,
            "type": vuln_type.strip(),
            "location": location,
            "code_snippet": code_snippet,
            "full_content": analysis_text[match.start():end_pos].strip(),
        })

    return vulnerabilities


def _batch_verify_vulnerabilities(vulnerabilities: list, api_type: str) -> list:
    """Verify all vulnerabilities in a single API call. Returns list of verification dicts."""
    if not vulnerabilities:
        return []

    vuln_lines = []
    for i, v in enumerate(vulnerabilities, 1):
        snippet = v["code_snippet"][:300] if v["code_snippet"] else "(no snippet)"
        vuln_lines.append(
            f"[{i}] Type={v['type']} | Severity={v['severity']} | Location={v['location']}\n"
            f"    Snippet: {snippet}"
        )

    prompt = (
        "You are a security verification expert. For each vulnerability listed below, "
        "determine if it is a TRUE POSITIVE or FALSE POSITIVE.\n\n"
        "For EACH item respond with exactly this format (one block per item, no extra text):\n\n"
        "ID: <number>\n"
        "Verdict: TRUE POSITIVE or FALSE POSITIVE\n"
        "Confidence: <0-100>\n"
        "Explanation: <one sentence>\n\n"
        "VULNERABILITIES TO VERIFY:\n\n"
        + "\n\n".join(vuln_lines)
    )

    try:
        client = APIClient(api_type)
        response = client.create_completion(
            messages=[
                {"role": "system", "content": "You are a security verification expert."},
                {"role": "user", "content": prompt}
            ],
            temperature=0,
            max_tokens=min(300 * len(vulnerabilities), 3000)
        )
        content = response.choices[0].message.content

        results = []
        for i in range(1, len(vulnerabilities) + 1):
            block_pattern = rf"ID:\s*{i}\s*\nVerdict:\s*(TRUE POSITIVE|FALSE POSITIVE)\s*\nConfidence:\s*(\d+)\s*\nExplanation:\s*([^\n]+)"
            m = re.search(block_pattern, content, re.IGNORECASE)
            if m:
                results.append({
                    "verdict": m.group(1).upper(),
                    "confidence": int(m.group(2)),
                    "explanation": m.group(3).strip(),
                })
            else:
                results.append({"verdict": "UNCERTAIN", "confidence": 50, "explanation": "Could not parse verification response."})
        return results

    except Exception as e:
        logging.error(f"Batch verification error: {str(e)}")
        return [{"verdict": "ERROR", "confidence": 0, "explanation": "Verification failed."} for _ in vulnerabilities]


def verify_all_vulnerabilities(analysis_text: str, api_type: str, confidence_threshold: str) -> str:
    """Verifies all vulnerabilities and filters based on confidence threshold."""
    vulnerabilities = extract_vulnerabilities(analysis_text)

    if not vulnerabilities:
        return analysis_text

    threshold_values = {"Low": 30, "Medium": 60, "High": 80}
    threshold = threshold_values.get(confidence_threshold, 60)

    verifications = _batch_verify_vulnerabilities(vulnerabilities, api_type)
    verified_vulnerabilities = []
    for vuln, verification in zip(vulnerabilities, verifications):
        vuln["verification"] = verification
        if verification["verdict"] == "TRUE POSITIVE" and verification["confidence"] >= threshold:
            verified_vulnerabilities.append(vuln)

    if not verified_vulnerabilities:
        return (
            "## [Secure] No Verified Vulnerabilities Detected\n\n"
            f"The initial analysis identified {len(vulnerabilities)} potential issues, "
            f"but none passed verification at the current confidence threshold ({confidence_threshold}).\n\n"
            "### Original Analysis (Not Verified)\n\n" + analysis_text
        )

    new_analysis = "## Summary\n\n"
    new_analysis += f"Found {len(verified_vulnerabilities)} verified vulnerabilities out of {len(vulnerabilities)} reported issues.\n\n"

    severity_counts: Dict[str, int] = {}
    for vuln in verified_vulnerabilities:
        sev = vuln["severity"]
        severity_counts[sev] = severity_counts.get(sev, 0) + 1

    emoji_map = {"Critical": "🔴", "High": "🟠", "Medium": "🟡", "Low": "🟢"}
    for severity, count in severity_counts.items():
        emoji = emoji_map.get(severity, "")
        new_analysis += f"- {emoji} {count} {severity}\n"

    new_analysis += "\n\n"

    for i, vuln in enumerate(verified_vulnerabilities, 1):
        updated_content = re.sub(
            r"##\s*\[(Critical|High|Medium|Low)\]\s*Vulnerability\s*#\d+:",
            f"## [{vuln['severity']}] Vulnerability #{i}:",
            vuln["full_content"]
        )
        verification_info = (
            f"\n\n**Verification:** Confirmed with {vuln['verification']['confidence']}% confidence\n"
            f"**Justification:** {vuln['verification']['explanation']}\n"
        )
        updated_content += verification_info
        new_analysis += updated_content + "\n\n"

    filtered_count = len(vulnerabilities) - len(verified_vulnerabilities)
    if filtered_count > 0:
        new_analysis += f"### Note\n\n{filtered_count} potential issue(s) were filtered out due to insufficient confidence.\n"

    return new_analysis


def build_json_report(analysis_results: str) -> dict:
    """Build a structured JSON report from raw analysis text."""
    vulnerabilities = extract_vulnerabilities(analysis_results)
    json_payload = {
        "generated_at": datetime.now().isoformat(),
        "summary": {
            "total": len(vulnerabilities),
            "by_severity": {},
        },
        "vulnerabilities": [
            {
                "number": v["number"],
                "type": v["type"],
                "severity": v["severity"],
                "location": v["location"],
                "code_snippet": v["code_snippet"],
                "verification": v.get("verification"),
            }
            for v in vulnerabilities
        ],
        "raw_analysis": analysis_results,
    }
    for v in vulnerabilities:
        sev = v["severity"]
        json_payload["summary"]["by_severity"][sev] = json_payload["summary"]["by_severity"].get(sev, 0) + 1
    return json_payload
