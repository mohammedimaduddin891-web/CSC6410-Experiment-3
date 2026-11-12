#!/usr/bin/env python3
"""CSC6410 Experiment 3 — Windows network collection and drift checking.

Run on the student's Windows computer (not inside Docker):
    py -3 exp3_collect.py baseline
    py -3 exp3_collect.py wifi_off

Uses the instructor-supplied host_schema.json and your intended.json.
The unredacted observed*.json files stay local. Upload *public.json only.
Review this AI-assisted starting code and document its use in your report.
"""

import argparse
import copy
import ipaddress
import json
import platform
import re
import socket
import subprocess
import time
from datetime import datetime
from pathlib import Path

from jsonschema import Draft202012Validator

ROOT = Path(__file__).resolve().parent
MODEL_KEY = "student-host:host"

# These are read-only PowerShell queries. No network settings are changed.
QUERIES = {
    "adapters": "Get-NetAdapter -IncludeHidden | Select-Object Name,InterfaceDescription,Status,MacAddress,MtuSize | ConvertTo-Json -Depth 6 -Compress",
    "addresses": "Get-NetIPAddress | Select-Object InterfaceAlias,AddressFamily,IPAddress,PrefixLength | ConvertTo-Json -Depth 6 -Compress",
    "routes": "Get-NetRoute -AddressFamily IPv4 -DestinationPrefix '0.0.0.0/0' | Select-Object InterfaceAlias,NextHop,RouteMetric | ConvertTo-Json -Depth 6 -Compress",
    "metrics": "Get-NetIPInterface -AddressFamily IPv4 | Select-Object InterfaceAlias,InterfaceMetric | ConvertTo-Json -Depth 6 -Compress",
    "dns": "Get-DnsClientServerAddress | Select-Object InterfaceAlias,AddressFamily,ServerAddresses | ConvertTo-Json -Depth 6 -Compress",
}


def items(value):
    if value is None:
        return []
    return value if isinstance(value, list) else [value]


def read_powershell(name, command):
    prefix = '[Console]::OutputEncoding = [System.Text.UTF8Encoding]::new($false); '
    proc = subprocess.run(
        ["powershell.exe", "-NoProfile", "-NonInteractive", "-Command", prefix + command],
        capture_output=True, text=True, encoding="utf-8", errors="replace", check=False,
    )
    if proc.returncode != 0:
        raise RuntimeError(f"PowerShell {name} failed: {proc.stderr.strip()}")
    content = proc.stdout.strip().lstrip("\ufeff")
    if not content:
        return []
    try:
        return items(json.loads(content))
    except json.JSONDecodeError as exc:
        raise RuntimeError(f"PowerShell {name} did not return JSON: {content[:300]}") from exc


def classify(name, description):
    n = name.lower()
    desc = description.lower()
    if "loopback" in n or "loopback" in desc:
        return "loopback"
    if "wi-fi direct" in desc or "virtual" in desc or "miniport" in desc or "nord" in desc:
        return "virtual"
    if "wi-fi" in n or "wifi" in n or "wireless" in desc or "802.11" in desc:
        return "wifi"
    if n == "ethernet" or ("ethernet" in desc and "kernel" not in desc):
        return "ethernet"
    return "virtual" if any(x in n + desc for x in ("vpn", "tunnel", "adapter", "teredo", "6to4")) else "other"


def valid_addr(ip, version):
    try:
        addr = ipaddress.ip_address(ip)
        return addr.version == version
    except ValueError:
        return False


def make_observed(raw, warnings):
    adapters, addresses, routes, metrics, dns = (raw[k] for k in QUERIES)
    by_name = {}
    for adapter in adapters:
        name = str(adapter.get("Name") or "").strip()
        if not name:
            continue
        status = str(adapter.get("Status") or "").lower()
        desc = str(adapter.get("InterfaceDescription") or "")
        entry = {
            "name": name,
            "type": classify(name, desc),
            "oper-status": "up" if status == "up" else "down",
        }
        mac = str(adapter.get("MacAddress") or "").strip().lower().replace("-", ":")
        if re.fullmatch(r"[0-9a-f]{2}(:[0-9a-f]{2}){5}", mac):
            entry["mac"] = mac
        elif mac:
            warnings.append(f"{name}: MAC '{mac}' was not in the model's format; optional MAC omitted")
        mtu = adapter.get("MtuSize")
        if mtu is not None and str(mtu).strip():
            try:
                n = int(mtu)
                if 68 <= n <= 65536:
                    entry["mtu"] = n
                else:
                    warnings.append(f"{name}: Windows reported MTU={n}, outside the schema's 68..65536 range; optional MTU omitted")
            except (ValueError, TypeError):
                warnings.append(f"{name}: nonnumeric MTU '{mtu}' omitted")
        by_name[name] = entry

    for item in addresses:
        name = str(item.get("InterfaceAlias") or "").strip()
        if not name:
            continue
        if name not in by_name:
            by_name[name] = {
                "name": name, "type": classify(name, ""),
                "oper-status": "up" if "loopback" in name.lower() else "down",
            }
        address = str(item.get("IPAddress") or "").split("%", 1)[0].strip()
        try:
            prefix = int(item.get("PrefixLength"))
        except (ValueError, TypeError):
            warnings.append(f"{name}: IP '{address}' has no numeric prefix; omitted")
            continue
        fam = str(item.get("AddressFamily") or "").lower()
        if fam in ("ipv4", "2") and valid_addr(address, 4) and 0 <= prefix <= 32:
            by_name[name].setdefault("ipv4", []).append(f"{address}/{prefix}")
        elif fam in ("ipv6", "23") and valid_addr(address, 6) and 0 <= prefix <= 128:
            by_name[name].setdefault("ipv6", []).append(f"{address}/{prefix}")
        else:
            warnings.append(f"{name}: unsupported address or prefix '{address}/{prefix}', family={fam}; omitted")

    for entry in by_name.values():
        for family in ("ipv4", "ipv6"):
            if family in entry:
                entry[family] = sorted(set(entry[family]))

    interface_metric = {}
    for item in metrics:
        name = str(item.get("InterfaceAlias") or "")
        try:
            interface_metric[name] = int(item.get("InterfaceMetric"))
        except (ValueError, TypeError):
            pass
    choices = []
    for route in routes:
        name = str(route.get("InterfaceAlias") or "")
        hop = str(route.get("NextHop") or "").strip()
        if not valid_addr(hop, 4) or hop == "0.0.0.0":
            continue
        try:
            route_metric = int(route.get("RouteMetric"))
        except (ValueError, TypeError):
            route_metric = 0
        metric = interface_metric.get(name, 0)
        choices.append((route_metric + metric, name, hop, route_metric, metric))
    choices.sort()
    if len(choices) > 1:
        warnings.append("Several IPv4 default routes exist; selected lowest (route metric + interface metric). VPN routing may require further verification")
    chosen_gateway = choices[0][2] if choices else None
    chosen_adapter = choices[0][1] if choices else ""

    dns_by_name = {}
    for row in dns:
        name = str(row.get("InterfaceAlias") or "")
        values = [str(v) for v in items(row.get("ServerAddresses")) if str(v).strip()]
        dns_by_name.setdefault(name, []).extend(values)
    dns_list = sorted(set(dns_by_name.get(chosen_adapter, [])))
    if not dns_list and "Wi-Fi" in dns_by_name:
        dns_list = sorted(set(dns_by_name["Wi-Fi"]))
        warnings.append("Default-route adapter had no DNS servers; used Wi-Fi DNS as fallback")

    host = {
        "hostname": socket.gethostname(),
        "os": "windows",
        "collected-at": datetime.now().astimezone().isoformat(timespec="seconds"),
        "interface": sorted(by_name.values(), key=lambda x: x["name"].lower()),
    }
    if chosen_gateway:
        host["default-gateway"] = chosen_gateway
    if dns_list:
        host["dns-server"] = dns_list
    return {MODEL_KEY: host}, choices, dns_by_name


def schema_errors(document, schema):
    validator = Draft202012Validator(schema)
    return sorted(validator.iter_errors(document), key=lambda e: (list(map(str, e.absolute_path)), e.message))


def fmt_path(error):
    return "/".join(str(x) for x in error.absolute_path) or "(root)"


def drift_lines(intended, observed):
    want = intended[MODEL_KEY]
    have = observed[MODEL_KEY]
    result = []
    for field, target in want.items():
        if field == "interface":
            have_by_name = {entry["name"]: entry for entry in have.get("interface", [])}
            for interface in target:
                name = interface["name"]
                actual = have_by_name.get(name)
                if actual is None:
                    result.append(f"interface {name}: intended present; observed missing")
                    continue
                for key, goal in interface.items():
                    if key == "name":
                        continue
                    seen = actual.get(key, "(missing)")
                    if seen != goal:
                        result.append(f"interface {name} / {key}: intended {json.dumps(goal)}; observed {json.dumps(seen)}")
        else:
            actual = have.get(field, "(missing)")
            if actual != target:
                result.append(f"host / {field}: intended {json.dumps(target)}; observed {json.dumps(actual)}")
    return result


def public_sample(document):
    safe = copy.deepcopy(document)
    host = safe[MODEL_KEY]
    host["hostname"] = "redacted-host"
    for row in host.get("interface", []):
        # MAC is optional in the schema: omit rather than insert xx (which breaks validation).
        row.pop("mac", None)
        for family in ("ipv4", "ipv6"):
            filtered = []
            for item in row.get(family, []):
                try:
                    if not ipaddress.ip_interface(item).ip.is_global:
                        filtered.append(item)
                except ValueError:
                    pass
            if filtered:
                row[family] = filtered
            else:
                row.pop(family, None)
    gateway = host.get("default-gateway")
    if gateway:
        try:
            if ipaddress.ip_address(gateway).is_global:
                host.pop("default-gateway", None)
        except ValueError:
            host.pop("default-gateway", None)
    host["dns-server"] = [
        item for item in host.get("dns-server", [])
        if _not_global(item)
    ]
    if not host["dns-server"]:
        host.pop("dns-server", None)
    return safe


def _not_global(item):
    try:
        return not ipaddress.ip_address(item).is_global
    except ValueError:
        return False


def main():
    parser = argparse.ArgumentParser(description="Read-only Windows network observation, schema validation, and intended-state drift")
    parser.add_argument("label", choices=("baseline", "wifi_off", "restored"))
    args = parser.parse_args()
    if platform.system().lower() != "windows":
        raise SystemExit("Run this on Windows PowerShell, not inside Docker/WSL")
    start = time.perf_counter()
    schema = json.loads((ROOT / "host_schema.json").read_text(encoding="utf-8-sig"))
    intended = json.loads((ROOT / "intended.json").read_text(encoding="utf-8-sig"))
    print("CSC6410 Experiment 3 — read-only Windows configuration collection")
    print("Stage:", args.label)
    print("System:", platform.platform())
    print("PowerShell commands used:")
    for name, query in QUERIES.items():
        print(f"  {name}: {query}")
    raw = {name: read_powershell(name, query) for name, query in QUERIES.items()}
    warnings = []
    observed, routes, dns = make_observed(raw, warnings)
    for out in (ROOT / "observed.json", ROOT / f"observed_{args.label}.json"):
        out.write_text(json.dumps(observed, indent=2) + "\n", encoding="utf-8")
    sample = public_sample(observed)
    for out in (ROOT / "observed_public.json", ROOT / f"observed_{args.label}_public.json"):
        out.write_text(json.dumps(sample, indent=2) + "\n", encoding="utf-8")
    errors = schema_errors(observed, schema)
    print(f"\nObserved {len(observed[MODEL_KEY]['interface'])} network interfaces")
    print("Default-route choices (metric total, interface, gateway, route metric, interface metric):")
    for route in routes:
        print("  ", route)
    if warnings:
        print("\nCollection/model compatibility notes:")
        for line in warnings:
            print(" -", line)
    print("\nSchema validation against host_schema.json:")
    if errors:
        for error in errors:
            print(f"  ERROR {fmt_path(error)}: {error.message}")
    else:
        print("  VALID: observed.json matches the professor's host_schema.json")
    differences = drift_lines(intended, observed)
    print("\nDrift compared with intended.json:")
    if differences:
        for line in differences:
            print("  DRIFT", line)
    else:
        print("  No differences in the explicitly monitored intended fields")
    elapsed = time.perf_counter() - start
    print(f"\nElapsed total collection + validation + drift: {elapsed:.3f} seconds")
    print("Files: observed.json (LOCAL ONLY), observed_public.json (redacted),")
    print(f"       observed_{args.label}.json, observed_{args.label}_public.json, drift_{args.label}.txt")
    (ROOT / f"drift_{args.label}.txt").write_text("\n".join(differences or ["No monitored drift"]) + "\n", encoding="utf-8")
    (ROOT / f"notes_{args.label}.txt").write_text("\n".join(warnings or ["No collection warnings"]) + "\n", encoding="utf-8")


if __name__ == "__main__":
    main()
