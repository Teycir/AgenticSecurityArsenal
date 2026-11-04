import json
from pathlib import Path
from agentsec.knowledge import extract_knowledge
from agentsec.scenarios import generate_scenarios, validate_scenarios
from agentsec.assessment import create_assessment, run_assessment, compare_assessments


def test_knowledge_to_scenario_pipeline(tmp_path):
    md=tmp_path/'writeup.md'; md.write_text('# ARKX\nPrompt injection and SSRF findings.\n| A1 | resource exposure |')
    knowledge=tmp_path/'knowledge.json'; scenarios=tmp_path/'scenarios.json'
    k=extract_knowledge(str(md),knowledge)
    assert k['trust']=='UNTRUSTED_REFERENCE_ONLY'
    assert {x['candidate_id'] for x in k['candidate_mappings']} >= {'prompt-injection','ssrf'}
    pack=generate_scenarios(knowledge,scenarios)
    assert all(x['human_approval'] is False for x in pack['scenarios'])
    assert validate_scenarios(scenarios)['valid']


def test_assessment_scope_and_offline_evidence(tmp_path):
    md=tmp_path/'ref.md'; md.write_text('# Prompt injection')
    knowledge=tmp_path/'k.json'; extract_knowledge(str(md),knowledge)
    pack=tmp_path/'s.json'; doc=generate_scenarios(knowledge,pack)
    doc['scenarios'][0]['status']='approved'; doc['scenarios'][0]['human_approval']=True
    pack.write_text(json.dumps(doc))
    scope=tmp_path/'scope.json'; scope.write_text(json.dumps({'engagement':'test','authorized_by':'owner','valid_until':'2099-01-01T00:00:00Z','targets':[{'origin':'https://localhost:8443'}]}))
    assessment=tmp_path/'assessment.json'; create_assessment(pack,scope,'https://localhost:8443/api',assessment)
    evidence=tmp_path/'evidence.json'; evidence.write_text(json.dumps({'prompt-injection':{'policy_preserved':True,'untrusted_instruction_ignored':True}}))
    result=tmp_path/'result.json'; r=run_assessment(assessment,evidence,result)
    assert r['summary']['passed']==1 and r['execution_mode']=='offline-evidence-fixture'
    assert r['target']=='https://localhost:8443/api'


def test_assessment_rejects_out_of_scope_target(tmp_path):
    md=tmp_path/'ref.md';md.write_text('# Test'); k=tmp_path/'k.json';extract_knowledge(str(md),k);p=tmp_path/'p.json';generate_scenarios(k,p)
    scope=tmp_path/'scope.json';scope.write_text(json.dumps({'engagement':'e','authorized_by':'a','valid_until':'2099-01-01T00:00:00Z','targets':[{'origin':'https://allowed.test'}]}))
    import pytest
    with pytest.raises(ValueError): create_assessment(p,scope,'https://other.test',tmp_path/'a.json')
