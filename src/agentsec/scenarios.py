"""Generate review-required assessment scenarios from knowledge records."""
from __future__ import annotations

import json
from pathlib import Path

def generate_scenarios(knowledge_path: str|Path, output: str|Path) -> dict:
    k=json.loads(Path(knowledge_path).read_text(encoding='utf-8'))
    if k.get('kind')!='agentsec-knowledge-reference' or k.get('trust')!='UNTRUSTED_REFERENCE_ONLY':
        raise ValueError('Input is not a valid untrusted AgentSec knowledge record')
    rows=[]
    for candidate in k.get('candidate_mappings',[]):
        rows.append({'id':candidate['candidate_id'],'name':candidate['candidate_id'].replace('-',' ').title(),
          'source':{'uri':k.get('source'),'sha256':k.get('sha256'),'candidate_terms':candidate.get('matched_terms',[])},
          'objective':f'Review whether the authorized system is resilient to {candidate["candidate_id"]}.',
          'checks':['define_safe_test','verify_control','capture_evidence','confirm_no_unauthorized_side_effect'],
          'expected':'Safe behavior consistent with the approved policy; no unauthorized side effects.',
          'status':'draft','human_approval':False,'execution_mode':'manual_or_synthetic_only'})
    doc={'schema_version':'1.0','kind':'agentsec-scenario-pack','source_sha256':k.get('sha256'),
         'trust':'UNTRUSTED_DRAFTS','scenarios':rows,
         'notice':'Generated scenarios are drafts. Review and approve individually; import does not authorize execution.'}
    p=Path(output); p.parent.mkdir(parents=True,exist_ok=True); p.write_text(json.dumps(doc,indent=2)+'\n',encoding='utf-8'); return doc

def validate_scenarios(path: str|Path) -> dict:
    d=json.loads(Path(path).read_text(encoding='utf-8')); errors=[]
    if d.get('kind')!='agentsec-scenario-pack': errors.append('kind must be agentsec-scenario-pack')
    ids=[]
    for i,s in enumerate(d.get('scenarios',[])):
        for field in ('id','name','objective','checks','source'):
            if not s.get(field): errors.append(f'scenarios[{i}] missing {field}')
        ids.append(s.get('id'))
        if s.get('human_approval') is not True and s.get('status')=='approved': errors.append(f'scenarios[{i}] approved without human_approval=true')
    if len(ids)!=len(set(ids)): errors.append('scenario IDs must be unique')
    return {'valid':not errors,'errors':errors,'scenario_count':len(ids),'executable_approved_count':sum(s.get('status')=='approved' and s.get('human_approval') is True for s in d.get('scenarios',[])),
            'note':'Validation is structural; it does not establish safety or authorization.'}
