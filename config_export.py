#!/usr/bin/env python3
"""
UniFi OS 5.x (UDM Pro / UDM Pro Max)

UniFi Config Exporter
- `--humanize-epochs` converts epoch timestamps (sec/ms) to offset-aware ISO 8601 in JSON outputs.
- Auto JSON→Excel per-site (`all_json.xlsx`), optional RAW sheets (`--json-excel-include-raw`).
- Opt-in aggregated JSON→Excel across sites (`--json-excel-aggregate` + `--json-excel-aggregate-include-raw`).
- Strip IDs/keys: `--strip-all-ids`, `--stripkeys`, `--stripkeys-file` (+ validator & exit-on-issues).
- Exact `--out-dir` (no timestamp appended), name-first ordering, consolidated `stat_device_combined.json`,
  firewall/NAT/traffic normalization, delta, lint-level validation, rule order, and controller-wide Excel export.
  Examples: 
    python unifi_config_export.py --url https://unifi.example.com --user admin --pass secret \
      --strip-all-ids --stripkeys-file stripkeys.txt --humanize-epochs \
      --json-excel-include-raw --json-excel-aggregate --json-excel-aggregate-include-raw

    python unifi_config_export.py --url https://unifi.example.com --user admin --pass secret \
      --out-dir ./unifi_export_output --skip-json-excel

    python unifi_config_export.py --url https://10.10.10.1 --user 'admin' --pass secret \
      --out-dir ./unifi_export_output --strip-all-ids --humanize-epochs --excel
"""

import argparse
import json
import os
import sys
import time
import datetime
import hashlib
import datetime as dt
from pathlib import Path
from typing import Dict, Any, List, Optional, Tuple, Set
from collections import OrderedDict, Counter
import requests
import pandas as pd
from requests import Session
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


DEFAULT_TIMEOUT = 15
DUMP_ROOT = Path.cwd()

# --------------------------- Utilities ---------------------------

def ts() -> str:
    return dt.datetime.now().strftime("%Y%m%d_%H%M%S")

def epoch() -> int:
    return int(time.time())

def join_url(base: str, *parts: str) -> str:
    return "/".join([base.rstrip("/")] + [p.strip("/") for p in parts])

def listify(x):
    if x is None:
        return []
    if isinstance(x, list):
        return x
    return [x]

def try_get(d: Dict[str, Any], *keys, default=None):
    cur = d
    for k in keys:
        if not isinstance(cur, dict) or k not in cur:
            return default
        cur = cur[k]
    return cur

# --------------------------- Stripping & Ordering ---------------------------

def parse_strip_sources(cli_arg: Optional[str], file_path: Optional[str]) -> Tuple[Set[str], Dict[str, Any]]:
    raw_tokens: List[str] = []
    source_counts = {"cli": 0, "file": 0}
    if cli_arg:
        for k in cli_arg.split(','):
            token = k.strip()
            source_counts["cli"] += 1
            raw_tokens.append(token)
    if file_path:
        p = Path(file_path)
        if not p.exists():
            raise FileNotFoundError(f"--stripkeys-file not found: {file_path}")
        content = p.read_text(encoding='utf-8')
        for raw in content.replace('\r','').split('\n'):
            line = raw.strip()
            if not line or line.startswith('#'):
                continue
            for token in line.split(','):
                token = token.strip()
                if token and not token.startswith('#'):
                    raw_tokens.append(token)
                    source_counts["file"] += 1
    empty_tokens = [t for t in raw_tokens if not t]
    non_empty = [t for t in raw_tokens if t]
    counts = Counter(non_empty)
    duplicates = sorted([t for t, c in counts.items() if c > 1])
    keys = set(non_empty)
    report = {
        "raw_tokens": raw_tokens,
        "empty_tokens": empty_tokens,
        "duplicates": duplicates,
        "source_counts": source_counts,
        "effective_count": len(keys),
    }
    return keys, report


def should_strip_key(k: str, strip_all_ids: bool, extra_strip: Set[str]) -> bool:
    if k in extra_strip:
        return True
    if strip_all_ids:
        if k in {"id", "site_id", "external_id"}:
            return True
        if k.endswith("_id"):
            return True
    return False


def strip_keys(obj: Any, strip_all_ids: bool = False, extra_strip: Optional[Set[str]] = None) -> Any:
    extra_strip = extra_strip or set()
    if isinstance(obj, dict):
        new = {}
        for k, v in obj.items():
            if should_strip_key(k, strip_all_ids, extra_strip):
                continue
            new[k] = strip_keys(v, strip_all_ids=strip_all_ids, extra_strip=extra_strip)
        return new
    elif isinstance(obj, list):
        return [strip_keys(x, strip_all_ids=strip_all_ids, extra_strip=extra_strip) for x in obj]
    else:
        return obj

# --------------------------- Epoch Humanizer ---------------------------

def _is_epoch_seconds(n: float) -> bool:
    return 1_000_000_000 <= n <= 10_000_000_000

def _is_epoch_millis(n: float) -> bool:
    return 1_000_000_000_000 <= n <= 10_000_000_000_000


def _to_iso(n: float, tz: dt.tzinfo) -> str:
    try:
        if _is_epoch_millis(n):
            n = n / 1000.0
        dt_obj = dt.datetime.fromtimestamp(n, tz=tz)
        return dt_obj.isoformat()
    except Exception:
        return str(n)


def humanize_epochs(obj: Any, tz: Optional[dt.tzinfo] = None) -> Any:
    """Recursively convert epoch-like numeric values to ISO-8601 strings.
    Handles ints/floats and digit-only strings.
    """
    if tz is None:
        tz = dt.datetime.now().astimezone().tzinfo
    if isinstance(obj, dict):
        out = {}
        for k, v in obj.items():
            out[k] = humanize_epochs(v, tz)
        return out
    elif isinstance(obj, list):
        return [humanize_epochs(x, tz) for x in obj]
    elif isinstance(obj, (int, float)):
        n = float(obj)
        if _is_epoch_seconds(n) or _is_epoch_millis(n):
            return _to_iso(n, tz)
        return obj
    elif isinstance(obj, str):
        s = obj.strip()
        if s.isdigit():
            try:
                n = float(s)
                if _is_epoch_seconds(n) or _is_epoch_millis(n):
                    return _to_iso(n, tz)
            except Exception:
                pass
        return obj
    else:
        return obj

# --------------------------- Ordering ---------------------------

def order_name_first(obj: Any, strip_all_ids: bool = False, extra_strip: Optional[Set[str]] = None) -> Any:
    obj = strip_keys(obj, strip_all_ids=strip_all_ids, extra_strip=extra_strip)
    if isinstance(obj, dict):
        if 'name' in obj:
            ordered = OrderedDict()
            ordered['name'] = obj['name']
            for k, v in obj.items():
                if k == 'name':
                    continue
                ordered[k] = order_name_first(v, strip_all_ids=strip_all_ids, extra_strip=extra_strip)
            return ordered
        else:
            return {k: order_name_first(v, strip_all_ids=strip_all_ids, extra_strip=extra_strip) for k, v in obj.items()}
    elif isinstance(obj, list):
        return [order_name_first(x, strip_all_ids=strip_all_ids, extra_strip=extra_strip) for x in obj]
    else:
        return obj

# --------------------------- JSON writer ---------------------------

def safe_write_json(path: Path, data: Any, strip_all_ids: bool = False, extra_strip: Optional[Set[str]] = None, humanize: bool = False) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    transformed = data
    try:
        if isinstance(data, dict):
            data = strip_keys(data, strip_all_ids=strip_all_ids, extra_strip=extra_strip)
            if 'payload' in data and isinstance(data['payload'], dict):
                payload = data['payload']
                if isinstance(payload.get('data'), list):
                    payload['data'] = [order_name_first(x, strip_all_ids=strip_all_ids, extra_strip=extra_strip) for x in payload['data']]
                    transformed = data
                else:
                    transformed = order_name_first(data, strip_all_ids=strip_all_ids, extra_strip=extra_strip)
            else:
                transformed = order_name_first(data, strip_all_ids=strip_all_ids, extra_strip=extra_strip)
        elif isinstance(data, list):
            transformed = [order_name_first(strip_keys(x, strip_all_ids=strip_all_ids, extra_strip=extra_strip), strip_all_ids=strip_all_ids, extra_strip=extra_strip) for x in data]
    except Exception:
        transformed = data

    if humanize:
        try:
            transformed = humanize_epochs(transformed)
        except Exception:
            pass

    with path.open("w", encoding="utf-8") as f:
        json.dump(transformed, f, ensure_ascii=False, indent=2)

# --------------------------- Stripkeys Validator ---------------------------

def validate_stripkeys(keys: Set[str], report: Dict[str, Any], strip_all_ids: bool) -> Dict[str, Any]:
    redundant_due_to_all_ids = []
    for k in keys:
        if strip_all_ids and (k in {"id", "site_id", "external_id"} or k.endswith("_id")):
            redundant_due_to_all_ids.append(k)
    suspicious = []
    for t in keys:
        if any(ch.isspace() for ch in t):
            suspicious.append(t)
    summary = {
        "duplicates": report.get("duplicates", []),
        "empty_tokens": report.get("empty_tokens", []),
        "redundant_due_to_strip_all_ids": sorted(set(redundant_due_to_all_ids)),
        "suspicious_tokens": sorted(set(suspicious)),
        "effective_keys": sorted(keys),
        "source_counts": report.get("source_counts", {}),
    }
    return summary


def write_validation(dump_root: Path, summary: Dict[str, Any]) -> Path:
    out = dump_root / "stripkeys_validation.txt"
    lines = []
    lines.append("StripKeys Validation Summary\n")
    lines.append(f"Source counts: {summary.get('source_counts')}\n")
    lines.append(f"Effective keys ({len(summary.get('effective_keys', []))}): {', '.join(summary.get('effective_keys', []))}\n")
    if summary.get('duplicates'):
        lines.append(f"Duplicates: {', '.join(summary['duplicates'])}\n")
    if summary.get('empty_tokens'):
        lines.append(f"Empty tokens: {', '.join(summary['empty_tokens'])}\n")
    if summary.get('redundant_due_to_strip_all_ids'):
        lines.append("Redundant due to --strip-all-ids: " + ', '.join(summary['redundant_due_to_strip_all_ids']) + "\n")
    if summary.get('suspicious_tokens'):
        lines.append("Suspicious tokens (contain whitespace): " + ', '.join(summary['suspicious_tokens']) + "\n")
    out.write_text(''.join(lines), encoding='utf-8')
    return out

# --------------------------- JSON→Excel Combiner ---------------------------

EXCEL_SHEET_LIMIT = 31

def sanitize_sheet_name(name: str) -> str:
    invalid = ":\\/?*[]"
    for ch in invalid:
        name = name.replace(ch, "-")
    name = name.strip() or "sheet"
    return name[:EXCEL_SHEET_LIMIT]


def extract_table_from_json(obj: Any) -> Tuple[pd.DataFrame, str]:
    if isinstance(obj, dict):
        payload = obj.get("payload")
        if isinstance(payload, dict):
            data = payload.get("data")
            if isinstance(data, list):
                try:
                    df = pd.json_normalize(data)
                    return df, "payload.data"
                except Exception:
                    pass
        data_raw = obj.get("payload_raw")
        if isinstance(data_raw, (list, dict)):
            try:
                df = pd.json_normalize(data_raw)
                return df, "payload_raw"
            except Exception:
                pass
        data2 = obj.get("data")
        if isinstance(data2, list):
            try:
                df = pd.json_normalize(data2)
                return df, "data"
            except Exception:
                pass
        for k, v in obj.items():
            if isinstance(v, list):
                try:
                    df = pd.json_normalize(v)
                    return df, k
                except Exception:
                    continue
    if isinstance(obj, list):
        try:
            df = pd.json_normalize(obj)
            return df, "root_list"
        except Exception:
            pass
    if isinstance(obj, dict):
        try:
            df = pd.json_normalize(obj)
            return df, "root_object"
        except Exception:
            pass
    return pd.DataFrame(), ""


def combine_json_dir_to_excel(base_dir: Path, out_path: Path, include_raw: bool = False) -> Optional[Path]:
    json_files = sorted([p for p in base_dir.glob("*.json")])
    csv_files = sorted([p for p in base_dir.glob("*.csv")])
    if not json_files and not csv_files:
        return None
    sheets: List[Tuple[str, pd.DataFrame]] = []
    raw_sheets: List[Tuple[str, pd.DataFrame]] = []
    used_names: Set[str] = set()
    def dedup(name: str) -> str:
        base = sanitize_sheet_name(name)
        if base not in used_names:
            used_names.add(base)
            return base
        suffix = 2
        while True:
            candidate = sanitize_sheet_name(f"{base}_{suffix}")
            if candidate not in used_names:
                used_names.add(candidate)
                return candidate
            suffix += 1
    for jf in json_files:
        try:
            obj = json.loads(jf.read_text(encoding="utf-8"))
        except Exception:
            continue
        df, _src = extract_table_from_json(obj)
        sheet_name = dedup(jf.stem)
        if not df.empty:
            sheets.append((sheet_name, df))
        else:
            if include_raw:
                raw_df = pd.DataFrame({"raw_json": [json.dumps(obj, ensure_ascii=False)]})
                raw_sheets.append((dedup(f"RAW_{jf.stem}"), raw_df))
    for cf in csv_files:
        try:
            df = pd.read_csv(cf)
            if not df.empty:
                sheets.append((dedup(cf.stem), df))
        except Exception:
            pass
    if not sheets and not raw_sheets:
        return None
    with pd.ExcelWriter(out_path, engine="openpyxl") as xw:
        for name, df in sheets:
            try:
                df.to_excel(xw, sheet_name=name, index=False)
            except Exception:
                pass
        for name, df in raw_sheets:
            try:
                df.to_excel(xw, sheet_name=name, index=False)
            except Exception:
                pass
    return out_path


def combine_all_sites_json_to_excel(root_dir: Path, out_path: Path, include_raw: bool = False) -> Optional[Path]:
    site_dirs = [p for p in root_dir.iterdir() if p.is_dir()]
    if not site_dirs:
        return None
    used_names: Set[str] = set()
    def dedup(name: str) -> str:
        base = sanitize_sheet_name(name)
        if base not in used_names:
            used_names.add(base)
            return base
        suffix = 2
        while True:
            candidate = sanitize_sheet_name(f"{base}_{suffix}")
            if candidate not in used_names:
                used_names.add(candidate)
                return candidate
            suffix += 1
    sheets: List[Tuple[str, pd.DataFrame]] = []
    raw_sheets: List[Tuple[str, pd.DataFrame]] = []
    for site in sorted(site_dirs):
        for jf in sorted(site.glob("*.json")):
            try:
                obj = json.loads(jf.read_text(encoding="utf-8"))
            except Exception:
                continue
            df, _src = extract_table_from_json(obj)
            sheet_base = f"{site.name}-{jf.stem}"
            sheet_name = dedup(sheet_base)
            if not df.empty:
                sheets.append((sheet_name, df))
            else:
                if include_raw:
                    raw_df = pd.DataFrame({"raw_json": [json.dumps(obj, ensure_ascii=False)]})
                    raw_sheets.append((dedup(f"RAW_{sheet_base}"), raw_df))
        for cf in sorted(site.glob("*.csv")):
            try:
                df = pd.read_csv(cf)
                if not df.empty:
                    sheets.append((dedup(f"{site.name}-{cf.stem}"), df))
            except Exception:
                pass
    if not sheets and not raw_sheets:
        return None
    with pd.ExcelWriter(out_path, engine="openpyxl") as xw:
        for name, df in sheets:
            try:
                df.to_excel(xw, sheet_name=name, index=False)
            except Exception:
                pass
        for name, df in raw_sheets:
            try:
                df.to_excel(xw, sheet_name=name, index=False)
            except Exception:
                pass
    return out_path

# --------------------------- Client ---------------------------

class UniFiOSClient:
    def __init__(self, base_url: str, username: str, password: str, verify_ssl: bool = False, timeout: int = DEFAULT_TIMEOUT):
        self.base_url = base_url.rstrip("/")
        self.username = username
        self.password = password
        self.verify_ssl = verify_ssl
        self.timeout = timeout
        self.session: Session = requests.Session()
        self.csrf_token: Optional[str] = None
        self.session.headers.update({
            "Accept": "application/json",
            "Content-Type": "application/json",
        })

    
    def login(self) -> None:
        """
        Log in to UniFi OS.
        - Sends rememberMe=True to stabilize session behavior.
        - Prefers bearer 'access_token' when provided by the console.
        - Falls back to CSRF token / cookies for older builds.
        - Verifies the session with a lightweight probe.
        """
        url = join_url(self.base_url, "api", "auth", "login")
        payload = {"username": self.username, "password": self.password, "rememberMe": True}

        r = self.session.post(url, json=payload, verify=self.verify_ssl, timeout=self.timeout)
        if r.status_code != 200:
            raise RuntimeError(f"Login failed: HTTP {r.status_code} - {r.text}")

        # Prefer bearer token (UniFi OS 5.x behavior on many consoles)
        access_token = None
        try:
            body = r.json()
            access_token = body.get("access_token") or body.get("token")
        except Exception:
            pass

        if access_token:
            self.session.headers["Authorization"] = f"Bearer {access_token}"

        # Maintain CSRF compatibility
        token = r.headers.get("X-CSRF-Token") or r.cookies.get("csrf_token")
        if token:
            self.csrf_token = token
            self.session.headers["X-CSRF-Token"] = token

        # Some consoles expect a Referer; harmless to include
        self.session.headers.setdefault("Referer", self.base_url)

        # Post-login probe to verify the session works for proxy/network calls
        probe_url = join_url(self.base_url, "proxy", "network", "api", "self")
        probe = self.session.get(probe_url, verify=self.verify_ssl, timeout=self.timeout)
        if probe.status_code != 200:
            raise RuntimeError(f"Post-login probe failed: HTTP {probe.status_code} - {probe.text}")

    def logout(self) -> None:
        url = join_url(self.base_url, "api", "logout")
        try:
            self.session.post(url, verify=self.verify_ssl, timeout=self.timeout)
        except Exception:
            pass

    def network_api(self, path: str) -> str:
        return join_url(self.base_url, "proxy", "network", path)

    def get_json(self, url: str, method: str = "GET", json_body: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        try:
            if method.upper() == "GET":
                resp = self.session.get(url, verify=self.verify_ssl, timeout=self.timeout)
            elif method.upper() == "POST":
                resp = self.session.post(url, json=json_body or {}, verify=self.verify_ssl, timeout=self.timeout)
            elif method.upper() == "PUT":
                resp = self.session.put(url, json=json_body or {}, verify=self.verify_ssl, timeout=self.timeout)
            else:
                raise ValueError(f"Unsupported method: {method}")

            out = {
                "status_code": resp.status_code,
                "url": url,
                "ok": resp.ok,
                "payload": {},
            }
            try:
                out["payload"] = resp.json()
            except Exception:
                out["payload_raw"] = resp.text
            return out
        except requests.RequestException as e:
            return {"status_code": None, "url": url, "ok": False, "error": str(e)}

    def list_sites(self) -> List[Dict[str, Any]]:
        urls = [
            self.network_api("api/self/sites"),
            self.network_api("api/stat/sites"),
        ]
        for u in urls:
            res = self.get_json(u)
            if res.get("ok") and isinstance(try_get(res, "payload", "data", default=[]), list):
                return res["payload"]["data"]
        return []

    def collect_site_data(self, site: str, out_dir: Path, strip_all_ids: bool = False, extra_strip: Optional[Set[str]] = None, humanize: bool = False) -> Dict[str, Any]:
        results: Dict[str, Any] = {}
        static_gets = [
            "stat/health","self","stat/ccode","stat/current-channel","stat/sysinfo","stat/event","stat/alarm","stat/sta",
            "stat/device-basic","stat/device","rest/setting","rest/firewallrule","rest/firewallgroup","rest/routing",
            "rest/wlanconf","rest/networkconf","rest/portconf","rest/dynamicdns","rest/user","stat/portforward","rest/portforward",
            "guest/s/{site}/hotspotconfig",
        ]

        for ep in static_gets:
            if ep.startswith("guest/s/"):
                url = join_url(self.base_url, "proxy", "network", ep.replace("{site}", site))
            else:
                url = self.network_api(f"api/s/{site}/{ep}")
            res = self.get_json(url)
            results[ep] = res
            safe_write_json(out_dir / f"{ep.replace('/', '_')}.json", res, strip_all_ids=strip_all_ids, extra_strip=extra_strip, humanize=humanize)

        # Consolidated device details
        devices_data = try_get(results, "stat/device", "payload", "data", default=[]) or []
        combined_items: List[OrderedDict] = []
        for d in devices_data:
            mac = d.get("mac")
            stats_url = self.network_api(f"api/s/{site}/stat/device/{mac}/stats")
            stats_res = self.get_json(stats_url)
            stats_payload = try_get(stats_res, "payload", "data", default={})
            top = OrderedDict()
            name_val = d.get("name")
            if name_val:
                top['name'] = name_val
            top['mac'] = mac
            top['type'] = d.get('type')
            top['model'] = d.get('model')
            top['model_name'] = d.get('model_name') or d.get('model')
            top['info'] = order_name_first(d, strip_all_ids=strip_all_ids, extra_strip=extra_strip)
            top['stats'] = order_name_first(stats_payload, strip_all_ids=strip_all_ids, extra_strip=extra_strip) if isinstance(stats_payload, (dict, list)) else stats_payload
            combined_items.append(top)
            time.sleep(0.03)

        combined_doc = {
            "endpoint": "stat/device",
            "site": site,
            "collected_at": epoch(),
            "count": len(combined_items),
            "data": combined_items,
        }
        if humanize:
            combined_doc = humanize_epochs(combined_doc)
        safe_write_json(out_dir / "stat_device_combined.json", combined_doc, strip_all_ids=strip_all_ids, extra_strip=extra_strip, humanize=False)

        # DPI site + client (by_app/by_cat)
        for ep in ["stat/sitedpi", "stat/stadpi"]:
            for d_type in ["by_app", "by_cat"]:
                url = self.network_api(f"api/s/{site}/{ep}")
                body = {"type": d_type}
                res = self.get_json(url, method="POST", json_body=body)
                results[f"{ep}:{d_type}"] = res
                safe_write_json(out_dir / f"{ep.replace('/', '_')}_{d_type}.json", res, strip_all_ids=strip_all_ids, extra_strip=extra_strip, humanize=humanize)
                time.sleep(0.05)

        # Sessions: last 24h
        now = epoch(); start = now - 24 * 3600
        url = self.network_api(f"api/s/{site}/stat/session?type=all&start={start}&end={now}")
        res = self.get_json(url)
        results["stat/session_24h"] = res
        safe_write_json(out_dir / "stat_session_24h.json", res, strip_all_ids=strip_all_ids, extra_strip=extra_strip, humanize=humanize)

        # Spectrum scan
        url = self.network_api(f"api/s/{site}/stat/spectrumscan")
        res = self.get_json(url)
        results["stat/spectrumscan"] = res
        safe_write_json(out_dir / "stat_spectrumscan.json", res, strip_all_ids=strip_all_ids, extra_strip=extra_strip, humanize=humanize)

        # Traffic rules v2
        url = join_url(self.base_url, "proxy", "network", f"v2/api/site/{site}/trafficrules")
        res = self.get_json(url)
        results["v2/api/site/{site}/trafficrules"] = res
        safe_write_json(out_dir / "v2_api_site_trafficrules.json", res, strip_all_ids=strip_all_ids, extra_strip=extra_strip, humanize=humanize)

        # Self endpoints
        for self_ep in ["api/self", "api/users/self"]:
            url = self.network_api(self_ep)
            res = self.get_json(url)
            results[self_ep] = res
            safe_write_json(out_dir / f"{self_ep.replace('/', '_')}.json", res, strip_all_ids=strip_all_ids, extra_strip=extra_strip, humanize=humanize)

        return results

# ---------------- Delta / Validation / Order / Excel ----------------

LINT_LEVELS = {"info": 1, "warning": 2, "error": 3}

def make_rule_key(row: pd.Series) -> str:
    base = f"{row.get('site','')}|{row.get('rule_type','')}|{row.get('rule_id','')}"
    if row.get('rule_id'):
        return base
    composite = "|".join([
        str(row.get('ruleset','')),
        str(row.get('name','')),
        str(row.get('action','')),
        str(row.get('src_groups','')),
        str(row.get('src_ips','')),
        str(row.get('src_ports','')),
        str(row.get('dst_groups','')),
        str(row.get('dst_ips','')),
        str(row.get('dst_ports','')),
        str(row.get('protocols','')),
    ])
    h = hashlib.sha1(composite.encode('utf-8')).hexdigest()[:12]
    return base + "|" + h


def compute_delta(current_df: pd.DataFrame, baseline_df: pd.DataFrame) -> pd.DataFrame:
    if baseline_df is None or baseline_df.empty:
        return pd.DataFrame(columns=["change_type", "key"]).assign(change_type="added")
    cur = current_df.copy(); base = baseline_df.copy()
    cur["key"] = cur.apply(make_rule_key, axis=1)
    base["key"] = base.apply(make_rule_key, axis=1)
    cur_keys = set(cur["key"]) if not cur.empty else set()
    base_keys = set(base["key"]) if not base.empty else set()
    added = cur[cur["key"].isin(cur_keys - base_keys)].assign(change_type="added")
    removed = base[base["key"].isin(base_keys - cur_keys)].assign(change_type="removed")
    intersect = cur_keys & base_keys
    cur_int = cur[cur["key"].isin(intersect)].set_index("key")
    base_int = base[base["key"].isin(intersect)].set_index("key")
    compare_cols = ["enabled","action","ruleset","logging","schedule","src_groups","src_ips","src_ports",
                    "dst_groups","dst_ips","dst_ports","protocols","description"]
    modified_rows = []
    for k in intersect:
        c = cur_int.loc[k]; b = base_int.loc[k]
        diffs = {}
        for col in compare_cols:
            if str(c.get(col,"")) != str(b.get(col,"")):
                diffs[col] = {"old": b.get(col,""), "new": c.get(col,"")}
        if diffs:
            row = {"key": k, "change_type": "modified"}
            for col, vals in diffs.items():
                row[f"{col}_old"] = vals["old"]; row[f"{col}_new"] = vals["new"]
            modified_rows.append(row)
    modified = pd.DataFrame(modified_rows)
    delta = pd.concat([added, removed, modified], ignore_index=True, sort=False)
    return delta


def policy_validation(df_all: pd.DataFrame, df_groups: pd.DataFrame, df_pf: pd.DataFrame) -> pd.DataFrame:
    """Validate firewall/port-forward policy. Robust to empty/missing columns.
    Returns a DataFrame of findings with columns: severity, severity_num, type, site, message.
    """
    findings: List[Dict[str, Any]] = []

    # If df_all is empty or None, nothing to validate
    if df_all is None or df_all.empty:
        return pd.DataFrame(columns=["severity","severity_num","type","site","message"])  # empty

    # Ensure required columns exist to avoid KeyError in groupby
    required_cols = [
        "site","rule_type","ruleset","action",
        "src_groups","src_ips","src_ports","dst_groups","dst_ips","dst_ports","protocols",
        "index","name","enabled","logging","schedule","description"
    ]
    for c in required_cols:
        if c not in df_all.columns:
            df_all[c] = ""

    # Duplicate rules info
    dup_cols = ["site","rule_type","ruleset","action","src_groups","src_ips","src_ports",
                "dst_groups","dst_ips","dst_ports","protocols"]
    try:
        df_dups = df_all.groupby(dup_cols, dropna=False).size().reset_index(name="count")
        for _, row in df_dups[df_dups["count"] > 1].iterrows():
            findings.append({
                "severity": "info", "severity_num": LINT_LEVELS["info"],
                "type": "duplicate_rule", "site": row.get("site"),
                "message": f"Duplicate rules detected (count={int(row['count'])}).",
            })
    except KeyError:
        pass

    # NAT overlap check
    if df_pf is not None and not df_pf.empty:
        for c in ["site","protocols","src_ports"]:
            if c not in df_pf.columns:
                df_pf[c] = ""
        try:
            df_pf_group = df_pf.groupby(["site","protocols","src_ports"], dropna=False).size().reset_index(name="count")
            for _, row in df_pf_group[df_pf_group["count"] > 1].iterrows():
                findings.append({
                    "severity": "warning", "severity_num": LINT_LEVELS["warning"],
                    "type": "nat_overlap", "site": row.get("site"),
                    "message": f"Port-forward overlap: protocol={row['protocols']} port={row['src_ports']} entries={int(row['count'])}",
                })
        except KeyError:
            pass

    # Unused firewall groups
    used_group_names = set()
    for col in ["src_groups","dst_groups"]:
        vals = df_all[col].dropna().tolist() if col in df_all.columns else []
        for val in vals:
            for g in str(val).split(";"):
                g = g.strip()
                if g:
                    used_group_names.add(g)
    if df_groups is not None and not df_groups.empty:
        if "name" not in df_groups.columns:
            df_groups["name"] = df_groups.get("group_name", "")
        for _, g in df_groups.iterrows():
            nm = str(g.get("name",""))
            if nm and nm not in used_group_names:
                findings.append({
                    "severity": "info", "severity_num": LINT_LEVELS["info"],
                    "type": "unused_group", "site": g.get("site"),
                    "message": f"Firewall group '{nm}' appears unused.",
                })

    # Empty selector rules
    for _, r in df_all.iterrows():
        if str(r.get("rule_type")) == "firewall":
            empty_src = (not str(r.get("src_groups")) and not str(r.get("src_ips")) and not str(r.get("src_ports")))
            empty_dst = (not str(r.get("dst_groups")) and not str(r.get("dst_ips")) and not str(r.get("dst_ports")))
            if empty_src and empty_dst:
                findings.append({
                    "severity": "error", "severity_num": LINT_LEVELS["error"],
                    "type": "empty_rule", "site": r.get("site"),
                    "message": f"Rule '{r.get('name')}' has no src/dst selectors.",
                })

    # Order-based shadowing/coverage
    df_idx = df_all[df_all.get("index").notna()] if "index" in df_all.columns else pd.DataFrame()
    if not df_idx.empty:
        df_idx["index"] = pd.to_numeric(df_idx["index"], errors="coerce")
        df_idx = df_idx.dropna(subset=["index"])

        def covers(broader: pd.Series, narrower: pd.Series) -> bool:
            def field_covers(a: str, b: str) -> bool:
                if not a:
                    return True  # broader 'any'
                if a == b:
                    return True
                aset = set([x.strip() for x in a.split(';') if x.strip()])
                bset = set([x.strip() for x in b.split(';') if x.strip()])
                return bset.issubset(aset)
            return (
                field_covers(str(broader.get("src_groups","")), str(narrower.get("src_groups",""))) and
                field_covers(str(broader.get("src_ips","")), str(narrower.get("src_ips",""))) and
                field_covers(str(broader.get("src_ports","")), str(narrower.get("src_ports",""))) and
                field_covers(str(broader.get("dst_groups","")), str(narrower.get("dst_groups",""))) and
                field_covers(str(broader.get("dst_ips","")), str(narrower.get("dst_ips",""))) and
                field_covers(str(broader.get("dst_ports","")), str(narrower.get("dst_ports",""))) and
                field_covers(str(broader.get("protocols","")), str(narrower.get("protocols","")))
            )

        for (site, ruleset), grp in df_idx.groupby(["site","ruleset"], dropna=False):
            grp_sorted = grp.sort_values("index")
            rows = list(grp_sorted.to_dict("records"))
            for i in range(len(rows)):
                for j in range(i+1, len(rows)):
                    r_i = rows[i]; r_j = rows[j]
                    if covers(r_i, r_j):
                        if (str(r_i.get("action")) == str(r_j.get("action"))):
                            findings.append({
                                "severity": "info", "severity_num": LINT_LEVELS["info"],
                                "type": "redundant_rule", "site": site,
                                "message": f"Rule '{r_j.get('name')}' (index {r_j.get('index')}) is covered by earlier '{r_i.get('name')}' (index {r_i.get('index')}).",
                            })
                        else:
                            findings.append({
                                "severity": "warning", "severity_num": LINT_LEVELS["warning"],
                                "type": "shadow_conflict", "site": site,
                                "message": f"Earlier '{r_i.get('action')}' rule '{r_i.get('name')}' may shadow later '{r_j.get('action')}' rule '{r_j.get('name')}'.",
                            })

    return pd.DataFrame(findings)


def export_rule_order(df_all: pd.DataFrame, site_dir: Path) -> Tuple[Path, pd.DataFrame]:
    df_ord = df_all.copy()
    if "index" in df_ord.columns:
        df_ord["index"] = pd.to_numeric(df_ord["index"], errors="coerce")
    cols = [
        "site","ruleset","rule_type","index","name","action","enabled","logging","schedule",
        "src_groups","src_ips","src_ports","dst_groups","dst_ips","dst_ports","protocols","description"
    ]
    cols = [c for c in cols if c in df_ord.columns]
    df_ord = df_ord[cols]
    sort_cols = [c for c in ["site","ruleset","rule_type","index"] if c in df_ord.columns]
    if sort_cols:
        df_ord = df_ord.sort_values(sort_cols, na_position='last')
    csv_path = site_dir / "rule_order.csv"
    df_ord.to_csv(csv_path, index=False)
    return csv_path, df_ord


def write_excel(out_path: Path, df_rules: pd.DataFrame, df_groups: pd.DataFrame, df_pf: pd.DataFrame, df_tr: pd.DataFrame, df_delta: pd.DataFrame, df_validation: pd.DataFrame, df_order: pd.DataFrame) -> Path:
    with pd.ExcelWriter(out_path, engine='openpyxl') as xw:
        df_rules.to_excel(xw, index=False, sheet_name='Rules')
        df_groups.to_excel(xw, index=False, sheet_name='Groups')
        df_pf.to_excel(xw, index=False, sheet_name='PortForwards')
        df_tr.to_excel(xw, index=False, sheet_name='TrafficRules')
        df_delta.to_excel(xw, index=False, sheet_name='Delta')
        df_validation.to_excel(xw, index=False, sheet_name='Validation')
        df_order.to_excel(xw, index=False, sheet_name='Order')
    return out_path


def find_latest_baseline(exclude: Path) -> Optional[Path]:
    parent = exclude.parent
    candidates = [p for p in parent.glob('unifi_dump_*') if p.is_dir() and p != exclude]
    if not candidates:
        return None
    candidates.sort()
    return candidates[-1]

# --------------------------- Main ---------------------------

def normalize_firewall_to_csv(site: str, results: Dict[str, Any], out_dir: Path) -> Tuple[Path, pd.DataFrame, pd.DataFrame, pd.DataFrame, pd.DataFrame]:
    rows: List[Dict[str, Any]] = []
    groups = try_get(results, "rest/firewallgroup", "payload", "data", default=[]) or []
    group_by_id: Dict[str, Dict[str, Any]] = {}
    group_rows: List[Dict[str, Any]] = []
    for g in groups:
        gid = g.get("_id"); name = g.get("name") or g.get("group_name"); type_ = g.get("type") or g.get("group_type")
        members = listify(g.get("members")) + listify(g.get("group_members")) + listify(g.get("addresses"))
        rendered_members = []
        for m in members:
            if isinstance(m, dict): rendered_members.append(m.get("ip") or m.get("port") or m.get("cidr") or m.get("value"))
            else: rendered_members.append(m)
        rendered_members = [x for x in rendered_members if x]
        group_rows.append({"site": site, "group_id": gid, "name": name, "type": type_, "members": ";".join(dict.fromkeys(rendered_members))})
        if gid: group_by_id[gid] = g

    def resolve_group_ids(ids: List[str]) -> Dict[str, Any]:
        names = []; members_flat = []
        for gid in ids:
            g = group_by_id.get(gid)
            if not g: continue
            nm = g.get("name") or g.get("group_name");
            if nm: names.append(nm)
            members = listify(g.get("members")) + listify(g.get("group_members")) + listify(g.get("addresses"))
            for m in members:
                if isinstance(m, dict): members_flat.append(m.get("ip") or m.get("port") or m.get("cidr") or m.get("value"))
                else: members_flat.append(m)
        names = list(dict.fromkeys([n for n in names if n])); members_flat = list(dict.fromkeys([m for m in members_flat if m]))
        return {"names": names, "members": members_flat}

    fw_rules = try_get(results, "rest/firewallrule", "payload", "data", default=[]) or []
    for r in fw_rules:
        rid = r.get("_id"); ruleset = r.get("ruleset") or r.get("rule_set"); name = r.get("name") or r.get("rule_name"); enabled = r.get("enabled"); action = r.get("action"); logging = r.get("log") or r.get("logging"); description = r.get("comment") or r.get("description"); schedule = r.get("schedule"); index = r.get("rule_index") or r.get("index")
        src_gids = listify(r.get("src_firewall_group_ids") or r.get("src_group_ids") or r.get("src_group_id")); dst_gids = listify(r.get("dst_firewall_group_ids") or r.get("dst_group_ids") or r.get("dst_group_id")); src_res = resolve_group_ids(src_gids); dst_res = resolve_group_ids(dst_gids)
        src_ips = listify(r.get("src_ip")) + listify(r.get("src_cidr")); dst_ips = listify(r.get("dst_ip")) + listify(r.get("dst_cidr")); src_ports = listify(r.get("src_port")); dst_ports = listify(r.get("dst_port")); protos = listify(r.get("protocol")) or listify(r.get("proto"))
        rows.append({"site": site, "rule_type": "firewall", "ruleset": ruleset, "rule_id": rid, "name": name, "enabled": enabled, "action": action, "logging": logging, "schedule": schedule, "index": index,
                     "src_groups": ";".join(src_res["names"]) if src_res["names"] else "",
                     "src_members": ";".join(src_res["members"]) if src_res["members"] else "",
                     "src_ips": ";".join([str(x) for x in src_ips if x]) if src_ips else "",
                     "src_ports": ";".join([str(x) for x in src_ports if x]) if src_ports else "",
                     "dst_groups": ";".join(dst_res["names"]) if dst_res["names"] else "",
                     "dst_members": ";".join(dst_res["members"]) if dst_res["members"] else "",
                     "dst_ips": ";".join([str(x) for x in dst_ips if x]) if dst_ips else "",
                     "dst_ports": ";".join([str(x) for x in dst_ports if x]) if dst_ports else "",
                     "protocols": ";".join([str(x) for x in protos if x]) if protos else "",
                     "description": description})

    pf_rules = try_get(results, "rest/portforward", "payload", "data", default=[]) or []
    pf_rows: List[Dict[str, Any]] = []
    for r in pf_rules:
        rid = r.get("_id"); name = r.get("name"); enabled = r.get("enabled"); src_ips = listify(r.get("src")) + listify(r.get("wan_ip")); protocol = r.get("protocol"); dport = r.get("dport") or r.get("external_port"); fwd_ip = r.get("fwd") or r.get("internal_ip"); fwd_port = r.get("fwd_port") or r.get("internal_port"); description = r.get("description") or r.get("comment")
        row = {"site": site, "rule_type": "portforward", "ruleset": "NAT", "rule_id": rid, "name": name, "enabled": enabled, "action": "dnat", "logging": r.get("log"), "schedule": r.get("schedule"), "index": r.get("index") or r.get("order"),
               "src_groups": "", "src_members": "",
               "src_ips": ";".join([str(x) for x in src_ips if x]) if src_ips else "",
               "src_ports": str(dport or ""),
               "dst_groups": "", "dst_members": "",
               "dst_ips": str(fwd_ip or ""),
               "dst_ports": str(fwd_port or ""),
               "protocols": str(protocol or ""),
               "description": description}
        rows.append(row); pf_rows.append(row)

    tr_rules = try_get(results, "v2/api/site/{site}/trafficrules", "payload", "data", default=[]) or []
    tr_rows: List[Dict[str, Any]] = []
    for r in tr_rules:
        rid = r.get("id") or r.get("_id"); name = r.get("name"); enabled = r.get("enabled"); action = r.get("action") or r.get("policy"); description = r.get("description") or r.get("comment"); src = listify(r.get("src")) + listify(r.get("source")); dst = listify(r.get("dst")) + listify(r.get("destination")); service = listify(r.get("service")) + listify(r.get("services")); schedule = r.get("schedule"); logging = r.get("logging") or r.get("log"); ruleset = r.get("ruleset") or r.get("direction"); index = r.get("index") or r.get("order")
        row = {"site": site, "rule_type": "trafficrule_v2", "ruleset": ruleset, "rule_id": rid, "name": name, "enabled": enabled, "action": action, "logging": logging, "schedule": schedule, "index": index,
               "src_groups": ";".join([str(x) for x in src if x]) if src else "", "src_members": "", "src_ips": "", "src_ports": "",
               "dst_groups": ";".join([str(x) for x in dst if x]) if dst else "", "dst_members": "", "dst_ips": "", "dst_ports": "",
               "protocols": ";".join([str(x) for x in service if x]) if service else "", "description": description}
        rows.append(row); tr_rows.append(row)

    df_all = pd.DataFrame(rows); df_groups = pd.DataFrame(group_rows); df_pf = pd.DataFrame(pf_rows); df_tr = pd.DataFrame(tr_rows)
    csv_path = out_dir / "firewall_rules.csv"; df_all.to_csv(csv_path, index=False)
    return csv_path, df_all, df_groups, df_pf, df_tr


def main():
    parser = argparse.ArgumentParser(description="UDM Pro/Max full suite v11a: humanize epoch timestamps, robust validation, opt-in aggregator & per-site Excel.")
    parser.add_argument("--url", default=os.getenv("UNIFI_URL"), required=not os.getenv("UNIFI_URL"), help="Base URL, e.g., https://udm-pro-max.local or https://udmp")
    parser.add_argument("--user", default=os.getenv("UNIFI_USER"), required=not os.getenv("UNIFI_USER"), help="Local admin username")
    parser.add_argument("--pass", dest="password", default=os.getenv("UNIFI_PASS"), required=not os.getenv("UNIFI_PASS"), help="Local admin password")
    parser.add_argument("--verify-ssl", action="store_true", help="Verify SSL certs (recommended when controller has a valid cert)")
    parser.add_argument("--timeout", type=int, default=DEFAULT_TIMEOUT, help="HTTP timeout in seconds")
    parser.add_argument("--baseline-dir", type=str, default=None, help="Path to previous unifi_dump_* directory for delta comparison")
    parser.add_argument("--excel", action="store_true", help="Write an Excel workbook with all sheets")
    parser.add_argument("--lint-level", type=str, choices=list(LINT_LEVELS.keys()), default="info", help="Minimum lint level to include in validation outputs")
    parser.add_argument("--strip-all-ids", action="store_true", help="Strip any key ending with _id and also id, site_id, external_id from all JSON exports")
    parser.add_argument("--stripkeys", type=str, default=None, help="Comma-separated list of extra keys to strip (e.g., secret,private_token)")
    parser.add_argument("--stripkeys-file", type=str, default=None, help="Path to a file listing extra keys to strip (one per line or comma-separated; '#' comments allowed)")
    parser.add_argument("--validate-stripkeys", action="store_true", help="Validate strip keys before running collection; writes a summary and prints to console")
    parser.add_argument("--validation-exit-on-issues", action="store_true", help="Exit non-zero if validation finds duplicates/empties/redundant/suspicious tokens")
    parser.add_argument("--out-dir", type=str, default=None, help="Exact output directory (no timestamp appended)")
    parser.add_argument("--skip-json-excel", action="store_true", help="Skip the final JSON→Excel combiner per site")
    parser.add_argument("--json-excel-include-raw", action="store_true", help="Include RAW sheet for non-tabular JSON files in the per-site site_unifi-export-datetime}.xlsx")
    parser.add_argument("--json-excel-aggregate", action="store_true", help="Create a controller-wide aggregated workbook of all sites' JSON files")
    parser.add_argument("--json-excel-aggregate-include-raw", action="store_true", help="Include RAW sheets for non-tabular JSONs in the aggregated workbook")
    parser.add_argument("--humanize-epochs", action="store_true", help="Convert epoch timestamps (sec/ms) to ISO 8601 strings in JSON outputs")
    parser.add_argument("--skip-policy-validation", action="store_true", help="Skip firewall/NAT/traffic policy validation step")
    args = parser.parse_args()

    # Parse and (optionally) validate extra strip keys
    try:
        extra_keys, parse_report = parse_strip_sources(args.stripkeys, args.stripkeys_file)
    except FileNotFoundError as e:
        print(f"[!] {e}"); sys.exit(2)

    # Output directory
    dump_root = Path(args.out_dir).resolve() if args.out_dir else (DUMP_ROOT / f"unifi_dump_{ts()}")
    dump_root.mkdir(parents=True, exist_ok=True)

    if args.validate_stripkeys:
        summary = validate_stripkeys(extra_keys, parse_report, args.strip_all_ids)
        print("[+] StripKeys Validation Summary")
        print(f"    Source counts: {summary.get('source_counts')}")
        print(f"    Effective keys ({len(summary.get('effective_keys', []))}): {', '.join(summary.get('effective_keys', []))}")
        if summary.get('duplicates'):
            print(f"    Duplicates: {', '.join(summary['duplicates'])}")
        if summary.get('empty_tokens'):
            print(f"    Empty tokens: {', '.join(summary['empty_tokens'])}")
        if summary.get('redundant_due_to_strip_all_ids'):
            print("    Redundant due to --strip-all-ids: " + ', '.join(summary['redundant_due_to_strip_all_ids']))
        if summary.get('suspicious_tokens'):
            print("    Suspicious tokens (contain whitespace): " + ', '.join(summary['suspicious_tokens']))
        path = write_validation(dump_root, summary)
        print(f"[+] Validation report written: {path}")
        issues = any([summary.get('duplicates'), summary.get('empty_tokens'), summary.get('redundant_due_to_strip_all_ids'), summary.get('suspicious_tokens')])
        if issues and args.validation_exit_on_issues:
            print("[!] Validation found issues; exiting due to --validation-exit-on-issues.")
            sys.exit(3)

    # Proceed with run using parsed extra_keys
    client = UniFiOSClient(args.url, args.user, args.password, verify_ssl=args.verify_ssl, timeout=args.timeout)
    print(f"[+] Logging into {args.url} ..."); client.login(); print("[+] Logged in.")

    print("[+] Discovering sites ..."); sites = client.list_sites()
    if not sites:
        print("[-] No sites discovered. Exiting."); client.logout(); sys.exit(2)
    safe_write_json(dump_root / "sites.json", sites, strip_all_ids=args.strip_all_ids, extra_strip=extra_keys, humanize=args.humanize_epochs)

    baseline_dir = Path(args.baseline_dir).resolve() if args.baseline_dir else find_latest_baseline(dump_root)
    if baseline_dir and baseline_dir.exists():
        print(f"[+] Using baseline directory: {baseline_dir}")
    else:
        if args.baseline_dir:
            print(f"[!] Baseline directory not found: {args.baseline_dir}")
        else:
            print("[i] No baseline directory detected; delta will show only 'added'.")
        baseline_dir = None

    all_rules_dfs = []; all_groups_dfs = []; all_pf_dfs = []; all_tr_dfs = []; delta_dfs = []; validation_dfs = []; order_dfs = []
    min_lint = LINT_LEVELS.get(args.lint_level, 1)

    for s in sites:
        site_short = s.get("name") or s.get("site_name") or "default"
        print(f"[+] Collecting site '{site_short}' ..."); site_dir = dump_root / site_short
        results = client.collect_site_data(site_short, site_dir, strip_all_ids=args.strip_all_ids, extra_strip=extra_keys, humanize=args.humanize_epochs)

        meta = {
            "site": site_short,
            "device_count": len(try_get(results, "stat/device", "payload", "data", default=[])),
            "client_active_count": len(try_get(results, "stat/sta", "payload", "data", default=[])),
            "event_count": len(try_get(results, "stat/event", "payload", "data", default=[])),
            "timestamp": ts(),
        }
        safe_write_json(site_dir / "_summary.json", meta, strip_all_ids=args.strip_all_ids, extra_strip=extra_keys, humanize=args.humanize_epochs)

        print(f"[+] Normalizing firewall/traffic/NAT for site '{site_short}' ...")
        csv_path, df_all, df_groups, df_pf, df_tr = normalize_firewall_to_csv(site_short, results, site_dir); print(f"[+] Wrote {csv_path}")
        all_rules_dfs.append(df_all); all_groups_dfs.append(df_groups); all_pf_dfs.append(df_pf); all_tr_dfs.append(df_tr)

        baseline_rules_df = None
        if baseline_dir:
            candidate = baseline_dir / site_short / "firewall_rules.csv"
            if candidate.exists():
                try:
                    baseline_rules_df = pd.read_csv(candidate)
                except Exception as e:
                    print(f"[!] Failed to read baseline CSV for site {site_short}: {e}")

        delta_df = compute_delta(df_all, baseline_rules_df if baseline_rules_df is not None else pd.DataFrame())
        delta_path = site_dir / "firewall_rules_delta.csv"; delta_df.to_csv(delta_path, index=False); print(f"[+] Wrote {delta_path}")
        delta_dfs.append(delta_df.assign(site=site_short))

        if not args.skip_policy_validation:
            val_df = policy_validation(df_all, df_groups, df_pf)
            val_df_filtered = val_df[val_df["severity_num"] >= min_lint] if not val_df.empty else val_df
            val_path = site_dir / f"policy_validation_{args.lint_level}.csv"; val_df_filtered.to_csv(val_path, index=False); print(f"[+] Wrote {val_path}")
            validation_dfs.append(val_df_filtered.assign(site=site_short))
        else:
            print("[i] Skipping policy validation for this run (per --skip-policy-validation).")

        order_csv_path, df_order_site = export_rule_order(df_all, site_dir); print(f"[+] Wrote {order_csv_path}")
        order_dfs.append(df_order_site.assign(site=site_short))

        # Final step: JSON→Excel combiner per site
        if not args.skip_json_excel:
            # Get Time Stamp for filename
            from datetime import datetime
            flag = "#" if os.name == "nt" else "-"
            filetimestamp = datetime.now().strftime("%m%d%y-%#H-%#M-%#S")
            out_xlsx = site_dir / f"site_unifi-export-{filetimestamp}.xlsx"
            res_path = combine_json_dir_to_excel(site_dir, out_xlsx, include_raw=args.json_excel_include_raw)
            if res_path:
                print(f"[+] JSON→Excel written: {res_path}")
            else:
                print(f"[i] JSON→Excel skipped (no suitable JSON files) for site '{site_short}'.")

        time.sleep(0.1)

    # Aggregate across sites (opt-in)
    # Get Time Stamp for filename
    from datetime import datetime
    flag = "#" if os.name == "nt" else "-"
    filetimestamp = datetime.now().strftime("%m%d%y-%#H-%#M-%#S")
    if args.json_excel_aggregate:
        agg_out = dump_root / f"all_unifi-export-{filetimestamp}.xlsx"
        res = combine_all_sites_json_to_excel(dump_root, agg_out, include_raw=args.json_excel_aggregate_include_raw)
        if res:
            print(f"[+] Aggregated JSON→Excel written: {res}")
        else:
            print("[i] Aggregated JSON→Excel skipped (no suitable JSON files across sites).")

    # Controller-wide Excel for firewall/NAT/traffic rules
    df_rules_all_sites = pd.concat(all_rules_dfs, ignore_index=True) if all_rules_dfs else pd.DataFrame()
    df_groups_all_sites = pd.concat(all_groups_dfs, ignore_index=True) if all_groups_dfs else pd.DataFrame()
    df_pf_all_sites = pd.concat(all_pf_dfs, ignore_index=True) if all_pf_dfs else pd.DataFrame()
    df_tr_all_sites = pd.concat(all_tr_dfs, ignore_index=True) if all_tr_dfs else pd.DataFrame()
    df_delta_all_sites = pd.concat(delta_dfs, ignore_index=True) if delta_dfs else pd.DataFrame()
    df_validation_all_sites = pd.concat(validation_dfs, ignore_index=True) if validation_dfs else pd.DataFrame()
    df_order_all_sites = pd.concat(order_dfs, ignore_index=True) if order_dfs else pd.DataFrame()
    print(f"[+] Export complete: {dump_root}")
    client.logout()


def run_export(
    url: str,
    user: str,
    password: str,
    out_dir,
    log_fn=print,
    humanize_epochs: bool = False,
    strip_all_ids: bool = False,
    excel: bool = True,
    json_excel_aggregate: bool = True,
    skip_policy_validation: bool = True,
    verify_ssl: bool = False,
    timeout: int = DEFAULT_TIMEOUT,
) -> Path:
    """Run the UniFi config export programmatically.
    Calls log_fn(msg) for progress instead of print().
    Returns the output directory Path on success.
    """
    from datetime import datetime
    out_dir = Path(out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    extra_keys: Set[str] = set()

    client = UniFiOSClient(url, user, password, verify_ssl=verify_ssl, timeout=timeout)
    log_fn(f"[+] Logging into {url} ...")
    client.login()
    log_fn("[+] Logged in.")

    log_fn("[+] Discovering sites ...")
    sites = client.list_sites()
    if not sites:
        log_fn("[-] No sites discovered.")
        client.logout()
        raise RuntimeError("No sites discovered")
    safe_write_json(out_dir / "sites.json", sites, strip_all_ids=strip_all_ids, extra_strip=extra_keys, humanize=humanize_epochs)

    baseline_dir = find_latest_baseline(out_dir)
    if baseline_dir and baseline_dir.exists():
        log_fn(f"[+] Using baseline directory: {baseline_dir}")
    else:
        log_fn("[i] No baseline directory detected; delta will show only 'added'.")
        baseline_dir = None

    all_rules_dfs = []; all_groups_dfs = []; all_pf_dfs = []; all_tr_dfs = []
    delta_dfs = []; validation_dfs = []; order_dfs = []
    min_lint = LINT_LEVELS.get("info", 1)

    for s in sites:
        site_short = s.get("name") or s.get("site_name") or "default"
        log_fn(f"[+] Collecting site '{site_short}' ...")
        site_dir = out_dir / site_short
        results = client.collect_site_data(site_short, site_dir, strip_all_ids=strip_all_ids, extra_strip=extra_keys, humanize=humanize_epochs)

        meta = {
            "site": site_short,
            "device_count": len(try_get(results, "stat/device", "payload", "data", default=[])),
            "client_active_count": len(try_get(results, "stat/sta", "payload", "data", default=[])),
            "event_count": len(try_get(results, "stat/event", "payload", "data", default=[])),
            "timestamp": ts(),
        }
        safe_write_json(site_dir / "_summary.json", meta, strip_all_ids=strip_all_ids, extra_strip=extra_keys, humanize=humanize_epochs)

        log_fn(f"[+] Normalizing firewall/traffic/NAT for site '{site_short}' ...")
        csv_path, df_all, df_groups, df_pf, df_tr = normalize_firewall_to_csv(site_short, results, site_dir)
        log_fn(f"[+] Wrote {csv_path}")
        all_rules_dfs.append(df_all); all_groups_dfs.append(df_groups)
        all_pf_dfs.append(df_pf); all_tr_dfs.append(df_tr)

        baseline_rules_df = None
        if baseline_dir:
            candidate = baseline_dir / site_short / "firewall_rules.csv"
            if candidate.exists():
                try:
                    baseline_rules_df = pd.read_csv(candidate)
                except Exception as e:
                    log_fn(f"[!] Failed to read baseline CSV: {e}")

        delta_df = compute_delta(df_all, baseline_rules_df if baseline_rules_df is not None else pd.DataFrame())
        delta_path = site_dir / "firewall_rules_delta.csv"
        delta_df.to_csv(delta_path, index=False)
        log_fn(f"[+] Wrote {delta_path}")
        delta_dfs.append(delta_df.assign(site=site_short))

        if not skip_policy_validation:
            val_df = policy_validation(df_all, df_groups, df_pf)
            val_df_filtered = val_df[val_df["severity_num"] >= min_lint] if not val_df.empty else val_df
            val_path = site_dir / "policy_validation_info.csv"
            val_df_filtered.to_csv(val_path, index=False)
            log_fn(f"[+] Wrote {val_path}")
            validation_dfs.append(val_df_filtered.assign(site=site_short))
        else:
            log_fn("[i] Skipping policy validation.")

        order_csv_path, df_order_site = export_rule_order(df_all, site_dir)
        log_fn(f"[+] Wrote {order_csv_path}")
        order_dfs.append(df_order_site.assign(site=site_short))

        if excel:
            flag = "#" if os.name == "nt" else "-"
            filetimestamp = datetime.now().strftime(f"%m%d%y-%{flag}H-%{flag}M-%{flag}S")
            out_xlsx = site_dir / f"site_unifi-export-{filetimestamp}.xlsx"
            res_path = combine_json_dir_to_excel(site_dir, out_xlsx, include_raw=False)
            if res_path:
                log_fn(f"[+] JSON→Excel written: {res_path}")
            else:
                log_fn(f"[i] JSON→Excel skipped for site '{site_short}'.")

        time.sleep(0.1)

    flag = "#" if os.name == "nt" else "-"
    filetimestamp = datetime.now().strftime(f"%m%d%y-%{flag}H-%{flag}M-%{flag}S")
    if json_excel_aggregate:
        agg_out = out_dir / f"all_unifi-export-{filetimestamp}.xlsx"
        res = combine_all_sites_json_to_excel(out_dir, agg_out, include_raw=False)
        if res:
            log_fn(f"[+] Aggregated JSON→Excel written: {res}")
        else:
            log_fn("[i] Aggregated JSON→Excel skipped.")

    log_fn(f"[+] Export complete: {out_dir}")
    client.logout()
    return out_dir


if __name__ == "__main__":
    main()
