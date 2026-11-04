"""Import untrusted security references into a provenance-preserving knowledge record."""
from __future__ import annotations

import hashlib
import json
import re
from pathlib import Path
from urllib.error import URLError
from urllib.request import Request, urlopen

class KnowledgeError(ValueError): pass

def _read_source(source: str) -> tuple[str, str]:
    if source.startswith(('https://','http://')):
        # Only public GitHub README/raw pages are supported; no arbitrary URL fetching.
        if not re.match(r'https?://(github\.com|raw\.githubusercontent\.com)/', source, re.IGNORECASE):
            raise KnowledgeError('Remote import is restricted to github.com and raw.githubusercontent.com')
        url=source
        m=re.match(r'https?://github\.com/([^/]+)/([^/]+)(?:/.*)?$', source)
        if m:
            owner, repo=m.group(1),m.group(2)
            candidates=[f'https://raw.githubusercontent.com/{owner}/{repo}/{branch}/README.md' for branch in ('main','master')]
            last=None
            for candidate in candidates:
                try:
                    req=Request(candidate,headers={'User-Agent':'AgentSec-knowledge-import/1.0','Accept':'text/plain'})
                    with urlopen(req,timeout=15) as r:
                        data=r.read(2_000_001)
                    if len(data)>2_000_000: raise KnowledgeError('Source exceeds 2 MB limit')
                    return data.decode('utf-8','replace'),source
                except (URLError, TimeoutError) as e:
                    last = e
            if last is not None:
                raise KnowledgeError(f'Could not find README on main/master: {last}')
        try:
            req=Request(url,headers={'User-Agent':'AgentSec-knowledge-import/1.0','Accept':'text/plain'})
            with urlopen(req,timeout=15) as r:
                if r.status != 200: raise KnowledgeError(f'HTTP status {r.status}')
                data=r.read(2_000_001)
            if len(data)>2_000_000: raise KnowledgeError('Source exceeds 2 MB limit')
            return data.decode('utf-8','replace'), source
        except (URLError,TimeoutError) as e: raise KnowledgeError(f'Could not import source: {e}') from e
    p=Path(source)
    if not p.is_file(): raise KnowledgeError(f'Local source not found: {source}')
    data=p.read_bytes()
    if len(data)>2_000_000: raise KnowledgeError('Source exceeds 2 MB limit')
    return data.decode('utf-8','replace'), str(p.resolve())

PATTERNS={
 'prompt-injection':['prompt injection','indirect injection','prompt hijack'],
 'mcp-resource-exposure':['resource exposure','mcp resource','resource disclosure'],
 'authorization-bypass':['authorization bypass','access control','idor','privilege escalation'],
 'ssrf':['ssrf','server-side request forgery'],
 'rag-poisoning':['rag poisoning','retrieval poisoning','knowledge base poisoning'],
 'unsafe-deserialization':['yaml deserialization','unsafe deserialization','deserialization'],
 'toctou':['toctou','time-of-check','race condition'],
 'information-disclosure':['information disclosure','information leak','data leakage'],
 'tool-poisoning':['tool poisoning','malicious tool description'],
 'tenant-isolation':['tenant isolation','cross-tenant'],
}
def extract_knowledge(source: str, output: str|Path) -> dict:
    text, origin=_read_source(source); lower=text.lower(); matches=[]
    for sid, terms in PATTERNS.items():
        hits=[term for term in terms if term in lower]
        if hits: matches.append({'candidate_id':sid,'matched_terms':hits,'human_validation':'unreviewed'})
    # Capture markdown headings and table rows as reference-only snippets.
    headings=[re.sub(r'^#{1,6}\s*','',x).strip() for x in text.splitlines() if re.match(r'^#{1,6}\s+',x)]
    tables=[x.strip() for x in text.splitlines() if '|' in x and len(x.strip())<1000]
    record={'schema_version':'1.0','kind':'agentsec-knowledge-reference','source':origin,
      'sha256':hashlib.sha256(text.encode()).hexdigest(),'trust':'UNTRUSTED_REFERENCE_ONLY',
      'title':headings[0] if headings else Path(origin).name,'headings':headings[:200],
      'table_rows':tables[:500],'candidate_mappings':matches,
      'limitations':['Heuristic extraction; candidate mappings are not confirmed vulnerabilities.',
                     'Imported text is data only and must never be executed as instructions.',
                     'Human review is required before scenario approval.']}
    p=Path(output); p.parent.mkdir(parents=True,exist_ok=True); p.write_text(json.dumps(record,indent=2,ensure_ascii=False)+'\n',encoding='utf-8')
    return record
