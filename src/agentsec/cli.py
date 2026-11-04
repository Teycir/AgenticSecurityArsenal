from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path

from agentsec.assessment import compare_assessments, create_assessment, run_assessment
from agentsec.catalog import filter_catalog, load_catalog, render_catalog
from agentsec.evaluations import list_evaluations, run_evaluations
from agentsec.findings import analyze_mcp_inventory, compare_reports
from agentsec.investigation import (
    analyze_openapi,
    generate_hypotheses,
    ingest_burp_xml,
    ingest_nmap_xml,
    ingest_nuclei_jsonl,
    scoped_http_probe,
)
from agentsec.investigation_engine import (
    create_investigation,
    investigation_report,
    next_action,
    record_result,
)
from agentsec.knowledge import extract_knowledge
from agentsec.labs import list_scenarios, run_labs
from agentsec.mcp_http import MCPHTTPError, inspect_http_server
from agentsec.mcp_inspector import (
    MCPInspectionError,
    inspect_stdio_server,
    parse_server_command,
    write_report,
)
from agentsec.planning import build_plan, render_plan_markdown, write_plan
from agentsec.sarif import to_sarif
from agentsec.scenarios import generate_scenarios, set_scenario_approval, validate_scenarios
from agentsec.scope import ScopeError, load_scope, require_target_in_scope


def _write_json_output(report: dict, destination: str) -> None:
    output = Path(destination)
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(report, indent=2, ensure_ascii=False) + "\\n", encoding="utf-8")


def main() -> int:
    parser = argparse.ArgumentParser(prog="agentsec", description="Agentic Security Arsenal")
    sub = parser.add_subparsers(dest="command", required=True)

    catalog_parser = sub.add_parser("catalog", help="List techniques in the knowledge base")
    catalog_parser.add_argument("--domain", action="append", help="Filter by exact domain; repeatable")
    catalog_parser.add_argument("--id", action="append", help="Filter by technique ID; repeatable")

    scope_parser = sub.add_parser("scope-check", help="Validate authorization scope")
    scope_parser.add_argument("manifest")
    scope_parser.add_argument("--target", help="Optional target URL to validate against an exact declared origin")

    plan_parser = sub.add_parser("plan", help="Generate a manual assessment plan; performs no network requests")
    plan_parser.add_argument("manifest")
    plan_parser.add_argument("--domain", action="append", help="Include an exact domain; repeatable")
    plan_parser.add_argument("--format", choices=("json", "markdown"), default="json")
    plan_parser.add_argument("--output", required=True, help="Output file path")

    mcp_parser = sub.add_parser("mcp-inspect", help="Passively inventory a local MCP stdio server")
    mcp_parser.add_argument("--command", dest="server_command", required=True, help="Server executable and arguments; parsed without a shell")
    mcp_parser.add_argument("--timeout", type=float, default=10.0, help="Per-request timeout in seconds (max 120)")
    mcp_parser.add_argument("--output", required=True, help="JSON report output path")

    http_parser = sub.add_parser("mcp-http-inspect", help="Scope-gated metadata inventory of a remote MCP Streamable HTTP endpoint")
    http_parser.add_argument("--url", required=True, help="Exact MCP endpoint URL")
    http_parser.add_argument("--scope", required=True, help="Authorization scope manifest")
    http_parser.add_argument("--timeout", type=float, default=10.0)
    http_parser.add_argument("--auth-env", help="Environment variable containing an authorized bearer token")
    http_parser.add_argument("--origin", help="Origin value to use for the Origin validation probe; defaults to https://agentsec.invalid")
    http_parser.add_argument("--output", required=True, help="JSON inventory report path")
    http_parser.add_argument("--sarif", help="Optional SARIF 2.1.0 output path")

    lab_parser = sub.add_parser("lab", help="Run deterministic, synthetic, local security labs")
    lab_sub = lab_parser.add_subparsers(dest="lab_command", required=True)
    lab_sub.add_parser("list", help="List available local training scenarios")
    lab_run = lab_sub.add_parser("run", help="Run one scenario or all local scenarios")
    lab_run.add_argument("--scenario", help="Exact scenario ID; omit to run all")
    lab_run.add_argument("--output", help="Optional JSON report output path")
    lab_run.add_argument("--sarif", help="Optional SARIF 2.1.0 output path")

    analyze_parser = sub.add_parser("analyze", help="Statically analyze a saved MCP inventory; no network access")
    analyze_parser.add_argument("inventory", help="JSON report produced by mcp-inspect or mcp-http-inspect")
    analyze_parser.add_argument("--output", required=True, help="Normalized findings JSON output")
    analyze_parser.add_argument("--sarif", help="Optional SARIF 2.1.0 output")

    diff_parser = sub.add_parser("compare", help="Compare baseline and current findings for regressions")
    diff_parser.add_argument("baseline")
    diff_parser.add_argument("current")
    diff_parser.add_argument("--output", required=True, help="JSON comparison output")

    eval_parser = sub.add_parser("eval", help="Run deterministic agent-security evaluations against supplied evidence; no live agent execution")
    eval_sub = eval_parser.add_subparsers(dest="eval_command", required=True)
    eval_sub.add_parser("list", help="List available evaluation scenarios")
    eval_run = eval_sub.add_parser("run", help="Evaluate a JSON evidence fixture")
    eval_run.add_argument("--evidence", help="JSON mapping of scenario IDs to boolean check evidence")
    eval_run.add_argument("--scenario", help="Run one exact scenario ID")
    eval_run.add_argument("--output", help="Optional JSON report output path")
    eval_run.add_argument("--sarif", help="Optional SARIF 2.1.0 output path")

    knowledge_parser = sub.add_parser("knowledge", help="Import untrusted CTF/writeup references")
    knowledge_sub = knowledge_parser.add_subparsers(dest="knowledge_command", required=True)
    knowledge_import = knowledge_sub.add_parser("import", help="Import local Markdown or GitHub reference")
    knowledge_import.add_argument("source")
    knowledge_import.add_argument("--output", required=True)
    scenario_parser = sub.add_parser("scenario", help="Generate and validate human-reviewed scenarios")
    scenario_sub = scenario_parser.add_subparsers(dest="scenario_command", required=True)
    scenario_gen = scenario_sub.add_parser("generate")
    scenario_gen.add_argument("--source", required=True)
    scenario_gen.add_argument("--output", required=True)
    scenario_val = scenario_sub.add_parser("validate")
    scenario_val.add_argument("pack")
    scenario_approve = scenario_sub.add_parser("approve", help="Explicitly approve reviewed scenarios")
    scenario_approve.add_argument("pack")
    scenario_approve.add_argument("--id", action="append", required=True, help="Scenario ID to approve; repeatable")
    scenario_revoke = scenario_sub.add_parser("revoke", help="Revoke approval and return scenarios to draft")
    scenario_revoke.add_argument("pack")
    scenario_revoke.add_argument("--id", action="append", required=True, help="Scenario ID to revoke; repeatable")
    assessment_parser = sub.add_parser("assessment", help="Create/run/compare offline evidence assessments")
    assessment_sub = assessment_parser.add_subparsers(dest="assessment_command", required=True)
    assessment_create = assessment_sub.add_parser("create")
    assessment_create.add_argument("--source", required=True)
    assessment_create.add_argument("--scope", required=True)
    assessment_create.add_argument("--target", required=True)
    assessment_create.add_argument("--output", required=True)
    assessment_run = assessment_sub.add_parser("run")
    assessment_run.add_argument("--assessment", required=True)
    assessment_run.add_argument("--evidence", required=True)
    assessment_run.add_argument("--output", required=True)
    assessment_compare = assessment_sub.add_parser("compare")
    assessment_compare.add_argument("--baseline", required=True)
    assessment_compare.add_argument("--current", required=True)
    assessment_compare.add_argument("--output", required=True)

    skills_parser = sub.add_parser("skills", help="Discover, inspect, and validate the bundled Agent Skills")
    skills_sub = skills_parser.add_subparsers(dest="skills_command", required=True)
    skills_sub.add_parser("list", help="List skills and their safety/parallel metadata")
    skill_show = skills_sub.add_parser("show", help="Print one complete SKILL.md and its metadata")
    skill_show.add_argument("name")
    skills_sub.add_parser("validate", help="Validate skill metadata and Agent Skills frontmatter")

    agent_parser = sub.add_parser("mcp-serve", help="Expose safe agent capabilities over MCP stdio")
    agent_parser.add_argument("--print-manifest", action="store_true", help="Print the agent capability manifest and exit")

    api_probe = sub.add_parser("http-probe", help="Make one bounded, scope-authorized HTTP GET request; redirects refused")
    api_probe.add_argument("--url", required=True)
    api_probe.add_argument("--scope", required=True)
    api_probe.add_argument("--timeout", type=float, default=8.0)
    api_probe.add_argument("--output", required=True)

    openapi_parser = sub.add_parser("openapi", help="Statically analyze an OpenAPI JSON document")
    openapi_parser.add_argument("document")
    openapi_parser.add_argument("--output", required=True)

    import_parser = sub.add_parser("import-scan", help="Import Nmap XML, Nuclei JSONL or Burp XML offline")
    import_parser.add_argument("--format", choices=("nmap_xml", "nuclei_jsonl", "burp_xml"), required=True)
    import_parser.add_argument("source")
    import_parser.add_argument("--output", required=True)

    hypothesis_parser = sub.add_parser("hypotheses", help="Generate unverified hypotheses from normalized report JSON files")
    hypothesis_parser.add_argument("reports", nargs="+")
    hypothesis_parser.add_argument("--output", required=True)

    inv_parser = sub.add_parser("investigation", help="Create and manage stateful evidence-led investigations")
    inv_sub = inv_parser.add_subparsers(dest="investigation_command", required=True)
    inv_create = inv_sub.add_parser("create", help="Create a scope-checked session from normalized report JSON")
    inv_create.add_argument("--scope", required=True)
    inv_create.add_argument("--target", required=True)
    inv_create.add_argument("--title", default="Security investigation")
    inv_create.add_argument("reports", nargs="+")
    inv_create.add_argument("--output", required=True)
    inv_next = inv_sub.add_parser("next", help="Get the next queued investigation action")
    inv_next.add_argument("session")
    inv_next.add_argument("--output", required=True)
    inv_record = inv_sub.add_parser("record", help="Record a human/agent supplied step outcome")
    inv_record.add_argument("session")
    inv_record.add_argument("--step-id", required=True)
    inv_record.add_argument("--outcome", choices=("observed", "not_observed", "inconclusive"), required=True)
    inv_record.add_argument("--note", required=True)
    inv_record.add_argument("--evidence-json", help="Optional JSON evidence value")
    inv_record.add_argument("--output", required=True)
    inv_report = inv_sub.add_parser("report", help="Render an investigation summary")
    inv_report.add_argument("session")
    inv_report.add_argument("--output", required=True)

    args = parser.parse_args()
    try:
        if args.command == "skills":
            from agentsec.skills import get_skill, list_skills, validate_skills
            if args.skills_command == "list":
                print(json.dumps(list_skills(), indent=2, ensure_ascii=False))
                return 0
            if args.skills_command == "show":
                skill = get_skill(args.name)
                print(json.dumps(skill["metadata"], indent=2, ensure_ascii=False))
                print("\n--- SKILL.md ---\n")
                print(skill["instructions"])
                return 0
            report = validate_skills()
            print(json.dumps(report, indent=2, ensure_ascii=False))
            return 0 if report["valid"] else 2
        if args.command == "http-probe":
            scope = load_scope(args.scope)
            report = scoped_http_probe(args.url, scope, timeout=args.timeout)
            _write_json_output(report, args.output)
            print(f"HTTP probe report written to {args.output}; status={report.get('http_status')}")
            return 0
        if args.command == "openapi":
            report = analyze_openapi(json.loads(Path(args.document).read_text(encoding="utf-8")))
            _write_json_output(report, args.output)
            print(f"OpenAPI analysis written to {args.output}; endpoints={report['endpoint_count']}")
            return 0
        if args.command == "import-scan":
            fn = {"nmap_xml": ingest_nmap_xml, "nuclei_jsonl": ingest_nuclei_jsonl, "burp_xml": ingest_burp_xml}[args.format]
            report = fn(args.source)
            _write_json_output(report, args.output)
            print(f"Imported {report.get('count', report.get('host_count', 0))} record(s) to {args.output}")
            return 0
        if args.command == "hypotheses":
            reports = [json.loads(Path(name).read_text(encoding="utf-8")) for name in args.reports]
            report = generate_hypotheses(*reports)
            _write_json_output(report, args.output)
            print(f"Generated {report['hypothesis_count']} unverified hypothesis(es) to {args.output}")
            return 0
        if args.command == "investigation":
            if args.investigation_command == "create":
                scope = load_scope(args.scope)
                reports = [json.loads(Path(name).read_text(encoding="utf-8")) for name in args.reports]
                report = create_investigation(scope, args.target, reports, args.title)
                _write_json_output(report, args.output)
                print(f"Investigation {report['session_id']} created with {len(report['steps'])} queued step(s)")
                print("Planning only: no validation steps were executed.")
                return 0
            session = json.loads(Path(args.session).read_text(encoding="utf-8"))
            if args.investigation_command == "next":
                report = next_action(session)
            elif args.investigation_command == "record":
                evidence = json.loads(args.evidence_json) if args.evidence_json else None
                report = record_result(session, args.step_id, args.outcome, args.note, evidence)
            else:
                report = investigation_report(session)
            _write_json_output(report, args.output)
            print(f"Investigation output written to {args.output}")
            return 0
        if args.command == "mcp-serve":
            from agentsec.agent_api import capability_manifest, serve_stdio
            if args.print_manifest:
                print(json.dumps(capability_manifest(), indent=2, ensure_ascii=False))
                return 0
            return serve_stdio()
        if args.command == "knowledge":
            record = extract_knowledge(args.source, args.output)
            mappings = len(record.get("candidate_mappings", []))
            print(
                f"Imported reference ({mappings} candidate mapping(s)); "
                f"untrusted source preserved at {args.output}"
            )
            return 0
        if args.command == "scenario":
            if args.scenario_command == "generate":
                doc = generate_scenarios(args.source, args.output)
                count = len(doc.get("scenarios", []))
                print(
                    f"Generated {count} draft scenario(s) at {args.output}; "
                    "none approved for execution"
                )
                return 0
            if args.scenario_command in {"approve", "revoke"}:
                approved = args.scenario_command == "approve"
                set_scenario_approval(args.pack, args.id, approved=approved)
                report = validate_scenarios(args.pack)
                if not report["valid"]:
                    raise ValueError("Updated scenario pack is invalid: " + "; ".join(report["errors"]))
                print(
                    f"{'Approved' if approved else 'Revoked'} {len(args.id)} scenario(s); "
                    f"{report['executable_approved_count']} approved total."
                )
                return 0
            report = validate_scenarios(args.pack)
            print(json.dumps(report, indent=2))
            return 0 if report["valid"] else 2
        if args.command == "assessment":
            if args.assessment_command == "create":
                doc = create_assessment(
                    args.source, args.scope, args.target, args.output
                )
                approved = len(doc.get("approved_scenarios", []))
                print(
                    f"Assessment created: {doc['assessment_id']} "
                    f"({approved} approved scenario(s)); evidence-only execution"
                )
                return 0
            if args.assessment_command == "run":
                report = run_assessment(
                    args.assessment, args.evidence, args.output
                )
                summary = report.get("summary", {})
                print(
                    f"Assessment evidence report written: {args.output}; {summary}"
                )
                return 0
            report = compare_assessments(
                args.baseline, args.current, args.output
            )
            summary = report.get("summary", {})
            print(
                f"Regression comparison written: {args.output}; {summary}"
            )
            return 0
        if args.command == "eval":
            if args.eval_command == "list":
                print(json.dumps(list_evaluations(), indent=2))
                return 0
            raw_evidence = (
                json.loads(Path(args.evidence).read_text(encoding="utf-8"))
                if args.evidence
                else {}
            )
            report = run_evaluations(raw_evidence, args.scenario)
            rendered = json.dumps(report, indent=2, ensure_ascii=False) + "\n"
            if args.output:
                output = Path(args.output)
                output.parent.mkdir(parents=True, exist_ok=True)
                output.write_text(rendered, encoding="utf-8")
                print(f"Evaluation report written to {output}")
            else:
                print(rendered, end="")
            if args.sarif:
                sarif_path = Path(args.sarif)
                sarif_path.parent.mkdir(parents=True, exist_ok=True)
                sarif_path.write_text(
                    json.dumps(to_sarif(report), indent=2) + "\n",
                    encoding="utf-8",
                )
                print(f"SARIF report written to {args.sarif}")
            print(f"Evaluation summary: {report['summary']}")
            print("Synthetic evidence only; no live model, tools, or target were contacted.")
            return 0
        if args.command == "analyze":
            source = json.loads(Path(args.inventory).read_text(encoding="utf-8"))
            report = analyze_mcp_inventory(source)
            output = Path(args.output)
            output.parent.mkdir(parents=True, exist_ok=True)
            output.write_text(
                json.dumps(report, indent=2, ensure_ascii=False) + "\n",
                encoding="utf-8",
            )
            if args.sarif:
                sarif_path = Path(args.sarif)
                sarif_path.parent.mkdir(parents=True, exist_ok=True)
                sarif_path.write_text(
                    json.dumps(to_sarif(report), indent=2) + "\n",
                    encoding="utf-8",
                )
            total = report.get("summary", {}).get("total", 0)
            print(f"Analysis written to {output}: {total} finding(s)")
            print("Static analysis only; no tools invoked or target contacted.")
            return 0
        if args.command == "compare":
            baseline = json.loads(Path(args.baseline).read_text(encoding="utf-8"))
            current = json.loads(Path(args.current).read_text(encoding="utf-8"))
            report = compare_reports(baseline, current)
            output = Path(args.output)
            output.parent.mkdir(parents=True, exist_ok=True)
            output.write_text(
                json.dumps(report, indent=2, ensure_ascii=False) + "\n",
                encoding="utf-8",
            )
            print(f"Comparison written to {output}: {report['summary']}")
            return 0
        if args.command == "lab":
            if args.lab_command == "list":
                print(json.dumps(list_scenarios(), indent=2))
                return 0
            report = run_labs(args.scenario)
            rendered = json.dumps(report, indent=2, ensure_ascii=False) + "\n"
            if args.output:
                out = Path(args.output)
                out.parent.mkdir(parents=True, exist_ok=True)
                out.write_text(rendered, encoding="utf-8")
                print(f"Lab report written to {out}")
            else:
                print(rendered, end="")
            if args.sarif:
                sarif_path = Path(args.sarif)
                sarif_path.parent.mkdir(parents=True, exist_ok=True)
                sarif_path.write_text(
                    json.dumps(to_sarif(report), indent=2) + "\n",
                    encoding="utf-8",
                )
                print(f"SARIF report written to {args.sarif}")
            summary = report.get("summary", {})
            print(
                f"Completed {summary.get('scenarios_run', 0)} local scenario(s); "
                f"{summary.get('findings', 0)} synthetic finding(s)."
            )
            print("No network access, external services, or real customer data were used.")
            return 0
        if args.command == "catalog":
            items = filter_catalog(load_catalog(), args.domain, args.id)
            print(render_catalog(items))
            return 0
        if args.command == "scope-check":
            scope = load_scope(args.manifest)
            if args.target:
                require_target_in_scope(args.target, scope)
                print(f"AUTHORIZED SCOPE MATCH: {args.target}")
            else:
                print(
                    f"Scope valid: {scope['engagement']} "
                    f"({len(scope['targets'])} target(s)); expires {scope['valid_until']}"
                )
            return 0
        if args.command == "mcp-http-inspect":
            scope = load_scope(args.scope)
            token = os.environ.get(args.auth_env) if args.auth_env else None
            if args.auth_env and token is None:
                raise MCPHTTPError(f"Environment variable {args.auth_env!r} is not set")
            report = inspect_http_server(
                args.url,
                scope,
                timeout=args.timeout,
                bearer_token=token,
                origin=args.origin,
            )
            output = Path(args.output)
            output.parent.mkdir(parents=True, exist_ok=True)
            output.write_text(
                json.dumps(report, indent=2, ensure_ascii=False) + "\n",
                encoding="utf-8",
            )
            if args.sarif:
                sarif_path = Path(args.sarif)
                sarif_path.parent.mkdir(parents=True, exist_ok=True)
                sarif_path.write_text(
                    json.dumps(to_sarif(report), indent=2) + "\n",
                    encoding="utf-8",
                )
            counts = {
                key: len(value.get("items", []))
                for key, value in report.get("inventory", {}).items()
            }
            print(f"MCP HTTP inventory written to {output}")
            print("Discovered: " + ", ".join(f"{key}={value}" for key, value in counts.items()))
            print("No tools invoked, resources read, prompts retrieved, or identities impersonated.")
            if args.sarif:
                print(f"SARIF report written to {args.sarif}")
            return 0
        if args.command == "mcp-inspect":
            command = parse_server_command(args.server_command)
            report = inspect_stdio_server(command, timeout=args.timeout)
            write_report(report, args.output)
            counts = {
                key: len(value.get("items", []))
                for key, value in report.get("inventory", {}).items()
            }
            print(f"MCP inventory written to {args.output}")
            print("Discovered: " + ", ".join(f"{key}={value}" for key, value in counts.items()))
            print("Passive mode: no tools invoked, resources read, or prompts retrieved.")
            return 0
        if args.command == "plan":
            scope = load_scope(args.manifest)
            plan = build_plan(scope, load_catalog(), args.domain)
            output = Path(args.output)
            output.parent.mkdir(parents=True, exist_ok=True)
            if args.format == "json":
                write_plan(plan, output)
            else:
                output.write_text(render_plan_markdown(plan), encoding="utf-8")
            technique_count = len(plan.get("techniques", []))
            print(f"Wrote {technique_count} manual test cases to {output}")
            print("No target was contacted; this command only generated a local plan.")
            return 0
    except (MCPHTTPError, MCPInspectionError, OSError, ScopeError, ValueError) as exc:
        print(f"DENIED: {exc}", file=sys.stderr)
        return 2
    return 1


if __name__ == "__main__":
    raise SystemExit(main())

