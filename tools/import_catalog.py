"""Translate reviewed native provider intents. Does not execute audit commands.

This intentionally parses the repository's narrow control layout, not general YAML.
Unrecognized checks remain present as explicit unsupported findings.
"""
import json
import re
import sys
from pathlib import Path

root = Path(__file__).resolve().parents[1]
source = Path(sys.argv[1]) if len(sys.argv) > 1 else root.parent / "ruleset" / "windows"
target = root / "rulesets"
target.mkdir(exist_ok=True)
password_fields = {
    "WIN-PWD-001": ("min_length", 1), "WIN-PWD-003": ("lockout_threshold", 1),
    "WIN-PWD-004": ("lockout_duration_seconds", 60), "WIN-PWD-005": ("lockout_window_seconds", 60),
    "WIN-PWD-006": ("max_age_seconds", 86400), "WIN-PWD-007": ("min_age_seconds", 86400),
    "WIN-PWD-008": ("history_length", 1),
}
wmi_fields = {
    "WIN-DEF-001":"MSFT_MpPreference.DisableRealtimeMonitoring",
    "WIN-DEF-002":"MSFT_MpPreference.MAPSReporting",
    "WIN-DEF-003":"MSFT_MpPreference.PUAProtection",
    "WIN-DEF-004":"MSFT_MpPreference.DisableScanningNetworkFiles",
    "WIN-DEF-005":"MSFT_MpPreference.EnableNetworkProtection",
    "WIN-SMB-003":"MSFT_SmbServerConfiguration.EnableSMB1Protocol",
    "WIN-SMB-005":"MSFT_SmbServerConfiguration.RequireSecuritySignature",
    "WIN-SMB-006":"MSFT_SmbClientConfiguration.RequireSecuritySignature",
}
approved_targets = {}
for platform in ("windows-10", "windows-11", "server-2022"):
    benchmark = (source / platform / "benchmark.yaml").read_text(encoding="utf-8")
    benchmark_id = platform + "-native-registry"
    rules = []
    for filename in sorted((source / platform).glob("[0-9]*.yaml")):
        text = filename.read_text(encoding="utf-8")
        for block in re.split(r"(?=^  - id: )", text, flags=re.M)[1:]:
            def field(name):
                value = re.search(r"^\s+(?:- )?" + name + r": (.+)$", block, re.M).group(1)
                return json.loads(value) if value.startswith('"') else value
            rule = {"id": field("id"), "title": field("title"), "severity": field("severity"),
                    "kind": "unsupported", "reason": "Native implementation pending for this policy check; no shell commands are executed."}
            audit = block.split("    audit:\n", 1)[1].split("    remediation:\n", 1)[0]
            command_match = re.search(r"      command: \|-\n(.*?)      expected:", audit, re.S)
            command = command_match.group(1).strip() if command_match else ""
            expected = json.loads(re.search(r"      expected: (.+)$", audit, re.M).group(1))
            comparison = re.search(r"      match: (.+)$", audit, re.M).group(1)
            direct = re.fullmatch(r"\(Get-ItemProperty -Path 'HKLM:\\([^']+)' -Name '([^']+)' -ErrorAction SilentlyContinue\)\.([A-Za-z0-9_]+)", command)
            nonempty = re.fullmatch(r"if \(\(Get-ItemProperty -Path 'HKLM:\\([^']+)' -Name '([^']+)' -ErrorAction SilentlyContinue\)\.([A-Za-z0-9_]+)\) \{ 'set' \} else \{ 'empty' \}", command)
            match = direct or nonempty
            if match and match.group(2).lower() == match.group(3).lower():
                if comparison in ("equals", "numeric_lte", "numeric_gte"):
                    rule.update(kind="registry", path=match.group(1), name=match.group(2),
                                match="nonempty" if nonempty else comparison, expected=expected)
                    del rule["reason"]
            if rule["id"] in password_fields:
                name, multiplier = password_fields[rule["id"]]
                rule.update(kind="password_policy", name=name, match=comparison, expected=str(int(expected)*multiplier))
            elif rule["id"].startswith("WIN-URA-"):
                name = re.search(r"\^(Se[A-Za-z]+)\\s", command).group(1)
                sids = expected.split("=", 1)[-1].replace("*", "").strip()
                rule.update(kind="user_right", name=name, match="set_contains" if comparison=="contains" else "set_equals", expected=sids)
                if rule["id"] == "WIN-URA-007":
                    rule.update(match="set_equals", expected="S-1-5-32-544,S-1-5-19,S-1-5-20,S-1-5-6")
            elif rule["id"].startswith("WIN-AUD-"):
                name = re.search(r'/subcategory:"([^"]+)"', command).group(1)
                rule.update(kind="audit_policy", name=name, match="equals", expected={"Success":"1","Failure":"2","Success and Failure":"3"}[expected])
            elif rule["id"].startswith("WIN-SVC-"):
                name = re.search(r"Get-Service -Name ([A-Za-z0-9]+)", command).group(1)
                rule.update(kind="service", name=name, match="equals", expected="Disabled")
            elif rule["id"]=="WIN-PWD-010":
                rule.update(kind="guest_account", name="Guest", match="equals", expected="False")
            elif rule["id"]=="WIN-DEF-007":
                rule.update(kind="installer_policy", name="AlwaysInstallElevated", match="equals", expected="0")
            elif rule["id"]=="WIN-SMB-010":
                rule.update(kind="anonymous_pipes", name="NullSessionPipes", match="equals", expected="none")
            elif rule["id"] in wmi_fields:
                rule.update(kind="wmi", name=wmi_fields[rule["id"]], match="equals", expected=expected)
            elif rule["id"].startswith("WIN-FW-"):
                profile, prop = re.fullmatch(r"\(Get-NetFirewallProfile -Name ([A-Za-z]+)\)\.([A-Za-z]+)", command).groups()
                rule.update(kind="firewall", name=profile+"."+prop, match=comparison, expected=expected)
            elif rule["id"] in ("WIN-PWD-002", "WIN-PWD-009"):
                rule.update(kind="password_flag", name="complexity" if rule["id"]=="WIN-PWD-002" else "reversible_storage", match="equals", expected="1" if rule["id"]=="WIN-PWD-002" else "0")
            if rule["kind"]!="unsupported":
                rule.pop("reason", None)
            native_target = (rule["kind"], rule.get("path", ""), rule.get("name", ""))
            if rule["id"] in approved_targets and approved_targets[rule["id"]] != native_target:
                raise ValueError("platform target difference needs an explicit platform allowlist: " + rule["id"])
            approved_targets[rule["id"]] = native_target
            rules.append(rule)
    result = {"version": "1", "benchmark_id": benchmark_id, "ruleset_version": "native-windows-5", "rules": rules}
    (target / (platform + ".json")).write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
    authoritative = source.parent / "native" / "windows" / platform / "registry.json"
    authoritative.parent.mkdir(parents=True, exist_ok=True)
    authoritative.write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
    supported = sum(r["kind"] != "unsupported" for r in rules)
    print(f"{platform}: {supported}/{len(rules)} native checks, {len(rules)-supported} explicit unsupported")
go_source = '// Code generated by tools/import_catalog.py; DO NOT EDIT.\npackage scanner\n\ntype approvedTarget struct { Kind,Path,Name string }\nvar approvedTargets = map[string]approvedTarget{\n'
for rule_id, metadata in sorted(approved_targets.items()):
    go_source += json.dumps(rule_id) + ': {' + ','.join(json.dumps(value) for value in metadata) + '},\n'
go_source += '}\n'
(root / 'internal' / 'scanner' / 'catalog_targets.go').write_text(go_source, encoding='utf-8')
