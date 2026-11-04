"""v1.4 static importers, safe HTTP probe and evidence-led hypotheses."""
from __future__ import annotations
import json
import re
import ssl
import urllib.error
import urllib.request
import xml.etree.ElementTree as ET
from pathlib import Path
from urllib.parse import urljoin, urlsplit

from agentsec.scope import require_target_in_scope

MAX_BODY = 1_000_000
USER_AGENT = "AgenticSecurityArsenal/1.6.0"


def _read_source(source: str) -> str:
    candidate = str(source)
    if candidate.lstrip().startswith(("<", "{", "{", "nmaprun")) or "\\n" in candidate:
        return candidate
    path = Path(candidate)
    return path.read_text(encoding="utf-8") if path.is_file() else candidate


def _load_json(path_or_text: str, label: str):
    try:
        raw = _read_source(path_or_text)
        return json.loads(raw)
    except (OSError, json.JSONDecodeError) as exc:
        raise ValueError(f"{label}: unable to parse JSON: {exc}") from exc


def analyze_openapi(document: dict) -> dict:
    if not isinstance(document, dict) or not isinstance(document.get("paths", {}), dict):
        raise ValueError("OpenAPI document must be an object with a paths object")
    findings, endpoints = [], []
    for path, item in document.get("paths", {}).items():
        if not isinstance(path, str) or not isinstance(item, dict):
            continue
        for method, operation in item.items():
            method = method.lower()
            if method not in {"get","post","put","patch","delete","options","head","trace"} or not isinstance(operation, dict):
                continue
            params = operation.get("parameters", [])
            security = operation.get("security", document.get("security", []))
            endpoints.append({"method": method.upper(), "path": path,
                              "operation_id": operation.get("operationId"),
                              "auth_declared": bool(security),
                              "parameter_count": len(params) if isinstance(params, list) else 0})
            if method in {"put", "patch", "delete", "post"}:
                findings.append({"id":"API_MUTATING_METHOD_EXPOSED", "severity":"info",
                    "confidence":"low", "endpoint":path, "method":method.upper(),
                    "evidence":"OpenAPI declares a state-changing HTTP method.",
                    "limitation":"Declaration only; authorization and runtime behavior are unverified."})
            if isinstance(params, list):
                for param in params:
                    if isinstance(param, dict) and param.get("in") == "path" and param.get("required") is not True:
                        findings.append({"id":"OPENAPI_OPTIONAL_PATH_PARAMETER","severity":"low",
                            "confidence":"medium","endpoint":path,"evidence":str(param.get("name")),
                            "limitation":"Schema anomaly candidate; validate intended API semantics."})
    return {"status":"ok","source":"openapi","openapi_version":document.get("openapi"),
            "title":document.get("info",{}).get("title") if isinstance(document.get("info"),dict) else None,
            "endpoint_count":len(endpoints),"endpoints":endpoints,"observations":findings,
            "network_access":False}


def ingest_nmap_xml(source: str) -> dict:
    raw = _read_source(source)
    try: root = ET.fromstring(raw)
    except ET.ParseError as exc: raise ValueError(f"Invalid Nmap XML: {exc}") from exc
    hosts=[]
    observations=[]
    for host in root.findall("host"):
        addr=host.find("address")
        ports=[]
        for port in host.findall("./ports/port"):
            state=port.find("state"); svc=port.find("service")
            record={"port":port.get("portid"),"protocol":port.get("protocol"),
                "state":state.get("state") if state is not None else None,
                "service":svc.get("name") if svc is not None else None,
                "product":svc.get("product") if svc is not None else None,
                "version":svc.get("version") if svc is not None else None}
            ports.append(record)
            if record["state"] == "open":
                observations.append({"id":"nmap-open-port","host":addr.get("addr") if addr is not None else None,
                    **record,"evidence":"Nmap XML reports this port as open."})
        hosts.append({"address":addr.get("addr") if addr is not None else None,"ports":ports})
    return {"status":"ok","source":"nmap_xml","hosts":hosts,"host_count":len(hosts),
            "observations":observations,"network_access":False}


def ingest_nuclei_jsonl(source: str) -> dict:
    raw=Path(source).read_text(encoding="utf-8") if Path(source).exists() else source
    records=[]
    for line_no,line in enumerate(raw.splitlines(),1):
        if not line.strip(): continue
        try: row=json.loads(line)
        except json.JSONDecodeError as exc: raise ValueError(f"Invalid Nuclei JSONL line {line_no}: {exc}") from exc
        if not isinstance(row,dict): raise ValueError(f"Nuclei line {line_no} must be an object")
        info=row.get("info") if isinstance(row.get("info"),dict) else {}
        records.append({"template_id":row.get("template-id") or row.get("templateID"),
            "name":info.get("name"),"severity":info.get("severity","unknown"),
            "matched_at":row.get("matched-at") or row.get("matched"),
            "type":row.get("type"),"evidence":row.get("extracted-results",[])})
    return {"status":"ok","source":"nuclei_jsonl","observations":records,"count":len(records),"network_access":False}


def ingest_burp_xml(source: str) -> dict:
    raw=Path(source).read_text(encoding="utf-8") if Path(source).exists() else source
    try: root=ET.fromstring(raw)
    except ET.ParseError as exc: raise ValueError(f"Invalid Burp XML: {exc}") from exc
    issues=[]
    for issue in root.findall(".//issue"):
        def val(tag):
            node=issue.find(tag)
            return "".join(node.itertext()).strip() if node is not None else None
        issues.append({"name":val("name"),"severity":val("severity"),"confidence":val("confidence"),
            "host":val("host"),"path":val("path"),"issue_type":val("type"),
            "description":val("issueBackground") or val("issueDetail"),
            "evidence":val("requestresponse")})
    return {"status":"ok","source":"burp_xml","observations":issues,"count":len(issues),"network_access":False}


def generate_hypotheses(*reports: dict) -> dict:
    hypotheses=[]
    for report in reports:
        if not isinstance(report,dict): continue
        source=report.get("source","unknown")
        rows=report.get("observations",[])
        for row in rows if isinstance(rows,list) else []:
            if not isinstance(row,dict): continue
            rid=row.get("id") or row.get("template_id") or row.get("name") or row.get("issue_type")
            hypotheses.append({"hypothesis_id":f"{source}:{str(rid or 'observation')[:80]}",
                "statement":f"Investigate whether this {source} observation represents an exploitable weakness.",
                "source":source,"evidence":row,"confidence":"unverified",
                "next_step":"Review raw evidence, confirm target is in scope, then validate with a benign, non-destructive check.",
                "status":"hypothesis_only"})
    return {"status":"ok","hypothesis_count":len(hypotheses),"hypotheses":hypotheses,
            "warning":"Hypotheses are not confirmed vulnerabilities; no exploitation was performed."}


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        raise urllib.error.HTTPError(req.full_url, code, "Redirect refused", headers, fp)


def scoped_http_probe(url: str, scope: dict, timeout: float=8.0, max_body: int=MAX_BODY) -> dict:
    """One bounded GET request; exact-origin scope, no redirects, no custom methods."""
    require_target_in_scope(url, scope)
    parsed=urlsplit(url)
    if parsed.username or parsed.password or parsed.fragment:
        raise ValueError("URL credentials and fragments are not accepted")
    if not 0.5 <= timeout <= 30: raise ValueError("timeout must be between 0.5 and 30 seconds")
    if not 1 <= max_body <= MAX_BODY: raise ValueError(f"max_body must be 1..{MAX_BODY}")
    request=urllib.request.Request(url,headers={"User-Agent":USER_AGENT,"Accept":"*/*"},method="GET")
    opener=urllib.request.build_opener(_NoRedirect(),urllib.request.HTTPSHandler(context=ssl.create_default_context()))
    try:
        with opener.open(request,timeout=timeout) as response:
            body=response.read(max_body+1)
            truncated=len(body)>max_body
            body=body[:max_body]
            return {"status":"ok","url":url,"http_status":response.status,
                "headers":dict(response.headers.items()),"body_bytes":len(body),
                "body_excerpt":body[:2048].decode("utf-8","replace"),
                "truncated":truncated,"method":"GET","redirects_followed":False,
                "scope_checked":True}
    except urllib.error.HTTPError as exc:
        return {"status":"http_error","url":url,"http_status":exc.code,
            "headers":dict(exc.headers.items()) if exc.headers else {},
            "body_excerpt":exc.read(min(max_body,2048)).decode("utf-8","replace"),
            "redirects_followed":False,"scope_checked":True}
