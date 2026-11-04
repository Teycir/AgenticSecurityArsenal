"""Assessment manifests, deterministic evidence evaluation, and regression diffs."""
from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path

from .evaluations import run_evaluations
from .scope import load_scope, require_target_in_scope

class AssessmentError(ValueError): pass

def create_assessment(scenarios_path, scope_path, target, output):
    pack=json.loads(Path(scenarios_path).read_text(encoding='utf-8'))
    if pack.get('kind')!='agentsec-scenario-pack': raise AssessmentError('Invalid scenario pack')
    scope=load_scope(scope_path); require_target_in_scope(target,scope)
    approved=[s for s in pack.get('scenarios',[]) if s.get('status')=='approved' and s.get('human_approval') is True]
    doc={'schema_version':'1.0','kind':'agentsec-assessment','assessment_id':hashlib.sha256((str(target)+str(datetime.now(timezone.utc))).encode()).hexdigest()[:16],
      'created_at':datetime.now(timezone.utc).isoformat(),'target':target,'scope_engagement':scope['engagement'],
      'scope_valid_until':scope['valid_until'],'scenario_pack':str(Path(scenarios_path).resolve()),
      'approved_scenarios':[s['id'] for s in approved],'draft_scenarios_excluded':len(pack.get('scenarios',[]))-len(approved),
      'execution':'evidence-fixture-only','status':'ready_for_evidence'}
    p=Path(output);p.parent.mkdir(parents=True,exist_ok=True);p.write_text(json.dumps(doc,indent=2)+'\n');return doc

def run_assessment(assessment_path,evidence_path,output):
    a=json.loads(Path(assessment_path).read_text()); ev=json.loads(Path(evidence_path).read_text())
    if a.get('kind')!='agentsec-assessment': raise AssessmentError('Invalid assessment manifest')
    # Existing evaluator is deterministic and never contacts the declared target.
    selected=a.get('approved_scenarios',[])
    report=run_evaluations(ev, None)
    report['assessment_id']=a['assessment_id'];report['target']=a['target'];report['execution_mode']='offline-evidence-fixture'
    if selected:
        report['scenarios']=[r for r in report['scenarios'] if r['id'] in selected]
    else:
        report['scenarios']=[]; report['summary']={'scenarios_run':0,'passed':0,'failed':0,'inconclusive':0}
    report['summary']={k:sum(r['status']==status for r in report['scenarios']) for k,status in [('passed','pass'),('failed','fail'),('inconclusive','inconclusive')]}
    report['summary']['scenarios_run']=len(report['scenarios'])
    report['limitations'].append('Assessment run used supplied evidence fixtures only; target was not contacted.')
    p=Path(output);p.parent.mkdir(parents=True,exist_ok=True);p.write_text(json.dumps(report,indent=2)+'\n');return report

def compare_assessments(baseline_path,current_path,output):
    b=json.loads(Path(baseline_path).read_text());c=json.loads(Path(current_path).read_text())
    bm={x['id']:x['status'] for x in b.get('scenarios',[])};cm={x['id']:x['status'] for x in c.get('scenarios',[])}
    rows=[]
    for sid in sorted(set(bm)|set(cm)):
        old=bm.get(sid,'not-run');new=cm.get(sid,'not-run')
        rows.append({'scenario':sid,'baseline':old,'current':new,'change':'improved' if old=='fail' and new=='pass' else ('regressed' if old=='pass' and new=='fail' else ('new' if old=='not-run' else 'unchanged'))})
    doc={'schema_version':'1.0','kind':'agentsec-regression','scenarios':rows,'summary':{'regressed':sum(x['change']=='regressed' for x in rows),'improved':sum(x['change']=='improved' for x in rows),'new':sum(x['change']=='new' for x in rows)}}
    p=Path(output);p.parent.mkdir(parents=True,exist_ok=True);p.write_text(json.dumps(doc,indent=2)+'\n');return doc
