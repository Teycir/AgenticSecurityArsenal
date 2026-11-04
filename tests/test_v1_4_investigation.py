import json
from http.server import BaseHTTPRequestHandler, HTTPServer
from threading import Thread
from datetime import datetime, timedelta, timezone
import pytest

from agentsec.investigation import (
    analyze_openapi, generate_hypotheses, ingest_burp_xml, ingest_nmap_xml,
    ingest_nuclei_jsonl, scoped_http_probe,
)
from agentsec.scope import ScopeError


def test_openapi_analysis_is_offline_and_finds_endpoints():
    report = analyze_openapi({"openapi":"3.1.0","info":{"title":"demo"},"paths":{
        "/users":{"get":{"operationId":"listUsers"},"post":{"summary":"create"}},
        "/users/{id}":{"delete":{}}
    }})
    assert report["endpoint_count"] == 3
    assert len(report["observations"]) == 2
    assert report["network_access"] is False


def test_nmap_xml_import():
    report = ingest_nmap_xml('<nmaprun><host><address addr="127.0.0.1"/><ports><port protocol="tcp" portid="8080"><state state="open"/><service name="http" product="test"/></port></ports></host></nmaprun>')
    assert report["hosts"][0]["ports"][0]["state"] == "open"
    assert report["observations"][0]["id"] == "nmap-open-port"
    assert generate_hypotheses(report)["hypothesis_count"] == 1


def test_nuclei_jsonl_import():
    report = ingest_nuclei_jsonl('{"template-id":"http-x","info":{"name":"Example","severity":"medium"},"matched-at":"https://lab.invalid"}')
    assert report["observations"][0]["severity"] == "medium"


def test_burp_xml_import():
    report = ingest_burp_xml('<issues><issue><name>Issue</name><severity>High</severity><host>https://lab.invalid</host><path>/x</path></issue></issues>')
    assert report["observations"][0]["name"] == "Issue"


def test_hypotheses_are_unverified():
    report = generate_hypotheses({"source":"nmap_xml","observations":[{"id":"open-port","port":8080}]})
    assert report["hypotheses"][0]["status"] == "hypothesis_only"


def _scope(url):
    return {"engagement":"test","authorized_by":"tester",
            "valid_until":(datetime.now(timezone.utc)+timedelta(hours=1)).isoformat(),
            "targets":[{"origin":url}]}


def test_http_probe_requires_exact_scope_and_get_only():
    class Handler(BaseHTTPRequestHandler):
        def do_GET(self):
            self.send_response(200); self.end_headers(); self.wfile.write(b"hello")
        def log_message(self, *args): pass
    server=HTTPServer(("127.0.0.1",0),Handler)
    thread=Thread(target=server.serve_forever,daemon=True); thread.start()
    try:
        origin=f"http://127.0.0.1:{server.server_port}"
        report=scoped_http_probe(origin+"/health",_scope(origin))
        assert report["http_status"] == 200
        assert report["body_excerpt"] == "hello"
        with pytest.raises(ScopeError):
            scoped_http_probe("http://127.0.0.1:1/",_scope("http://example.invalid"))
    finally:
        server.shutdown(); thread.join()


def test_new_mcp_capabilities_are_discoverable_and_callable():
    from agentsec.agent_api import capability_definitions, call_capability, capability_manifest
    names = {item["name"] for item in capability_definitions()}
    assert {"http_get_probe", "openapi_analyze", "scan_result_import", "hypothesis_generate"} <= names
    assert capability_manifest()["version"] == "1.6.0"
    result = call_capability("scan_result_import", {
        "format": "nmap_xml",
        "content": '<nmaprun><host><address addr="127.0.0.1"/></host></nmaprun>'
    })
    assert result["host_count"] == 1
