import os, json, hashlib
from datetime import datetime, timezone
import streamlit as st

st.set_page_config(page_title="GraphSentinel AI", page_icon="🛡️", layout="wide")
st.markdown("""<style>
.block-container{padding-top:1.5rem;max-width:1250px} .hero{padding:22px;border-radius:16px;background:linear-gradient(120deg,#101827,#172d45);border:1px solid #29445e} .muted{color:#9fb2c8}
</style>""", unsafe_allow_html=True)

# FalkorDB is the source of truth when configured. Local demo mode is explicitly labelled.
try:
    from falkordb import FalkorDB
except Exception:
    FalkorDB = None

HOST=os.getenv("FALKORDB_HOST", "")
PORT=int(os.getenv("FALKORDB_PORT", "6379"))
PASSWORD=os.getenv("FALKORDB_PASSWORD", "")
GRAPH_NAME=os.getenv("FALKORDB_GRAPH", "graphsentinel")

@st.cache_resource
def connect_graph():
    if not HOST or FalkorDB is None:
        return None, "Local demo mode — configure FalkorDB Cloud to persist graph data."
    try:
        client=FalkorDB(host=HOST, port=PORT, password=PASSWORD or None, ssl=os.getenv("FALKORDB_SSL","true").lower()=="true")
        return client.select_graph(GRAPH_NAME), "Connected to FalkorDB"
    except Exception as e:
        return None, f"FalkorDB connection failed: {e}"

graph, connection_status=connect_graph()

NODES=[
 {"id":"ip-203","label":"IP Address","name":"203.0.113.77","kind":"ip","risk":92,"detail":"Unusual login source; synthetic demo indicator"},
 {"id":"dev-17","label":"Device","name":"DEV-17","kind":"device","risk":65,"detail":"Device observed across multiple accounts"},
 {"id":"usr-104","label":"User","name":"alex.chen","kind":"user","risk":84,"detail":"Privileged access to production systems"},
 {"id":"usr-208","label":"User","name":"morgan.lee","kind":"user","risk":71,"detail":"Repeated authentication failures"},
 {"id":"svc-pay","label":"Service","name":"payments-api","kind":"service","risk":95,"detail":"Critical production service"},
 {"id":"alert-9","label":"Alert","name":"ALERT-009","kind":"alert","risk":88,"detail":"Impossible-travel login alert"},
 {"id":"ticket-42","label":"Incident","name":"INC-042","kind":"incident","risk":55,"detail":"Prior synthetic incident with shared device"},
]
EDGES=[("ip-203","dev-17","SEEN_ON"),("dev-17","usr-104","USED_BY"),("dev-17","usr-208","USED_BY"),("usr-104","svc-pay","CAN_ACCESS"),("alert-9","ip-203","OBSERVED_IP"),("alert-9","usr-104","FLAGS_USER"),("ticket-42","dev-17","INVOLVED_DEVICE"),("usr-208","svc-pay","CAN_ACCESS")]

SEED="""
UNWIND $nodes AS n
MERGE (x:Entity {id:n.id}) SET x.name=n.name, x.kind=n.kind, x.risk=n.risk, x.detail=n.detail
"""
EDGE_QUERY="""
UNWIND $edges AS e
MATCH (a:Entity {id:e[0]}), (b:Entity {id:e[1]})
MERGE (a)-[r:RELATES_TO {kind:e[2]}]->(b)
"""

def run_query(q, params=None):
    if graph is None: return None
    return graph.query(q, params or {})

def seed_graph():
    if graph is not None:
        run_query(SEED, {"nodes":NODES})
        run_query(EDGE_QUERY, {"edges":[list(e) for e in EDGES]})

def investigate(target):
    # This graph traversal, not a text-only model, drives the decision.
    if graph is not None:
        q="""
        MATCH (t:Entity {id:$target})
        OPTIONAL MATCH p=(t)-[:RELATES_TO*1..4]-(n:Entity)
        WITH t, collect(DISTINCT {id:n.id,name:n.name,kind:n.kind,risk:n.risk,detail:n.detail}) AS neighbors,
             collect(DISTINCT [x IN nodes(p) | coalesce(x.name,x.id)]) AS paths
        RETURN t.id, t.name, t.kind, t.risk, neighbors, paths
        """
        try:
            result=run_query(q,{"target":target})
            if result and result.result_set:
                row=result.result_set[0]
                return {"target":target,"neighbors":row[4] or [],"paths":row[5] or [],"source":"FalkorDB Cypher traversal"}
        except Exception as e:
            st.error(f"Graph query error: {e}")
    # Clearly labelled synthetic offline preview for immediate UI testing only.
    adjacency={n['id']:[] for n in NODES}
    for a,b,r in EDGES:
        adjacency[a].append((b,r)); adjacency[b].append((a,r))
    seen={target}; queue=[(target,[target])]; paths=[]; found=[]
    while queue:
        cur,path=queue.pop(0)
        if len(path)>1: paths.append([next((n['name'] for n in NODES if n['id']==x),x) for x in path])
        for nxt,rel in adjacency.get(cur,[]):
            if nxt not in seen:
                seen.add(nxt); queue.append((nxt,path+[nxt]))
                found.append(next((n for n in NODES if n['id']==nxt),{"id":nxt,"name":nxt,"kind":"unknown","risk":0,"detail":""}))
    return {"target":target,"neighbors":found,"paths":paths[:12],"source":"Local synthetic preview (not persisted)"}

def log_decision(target, score, action, evidence):
    if graph is not None:
        run_query("""CREATE (d:Decision {id:$id, target:$target, score:$score, action:$action, evidence:$evidence, created_at:$created})""", {
            "id":hashlib.sha1(f"{target}{datetime.now(timezone.utc).isoformat()}".encode()).hexdigest()[:12],
            "target":target,"score":score,"action":action,"evidence":json.dumps(evidence),"created":datetime.now(timezone.utc).isoformat()})

def read_decisions():
    if graph is None: return []
    try:
        r=run_query("MATCH (d:Decision) RETURN d.target,d.score,d.action,d.created_at ORDER BY d.created_at DESC LIMIT 10")
        return r.result_set if r else []
    except Exception: return []

st.markdown('<div class="hero"><h1>🛡️ GraphSentinel AI</h1><p class="muted">Explainable threat investigation powered by connected context · Graph Hacks 2026</p></div>',unsafe_allow_html=True)
col1,col2=st.columns([3,1]); col1.caption("Investigate relationships. Score risk. Explain the path. Recommend a safe response."); col2.caption("● "+connection_status)
with st.sidebar:
    st.header("Investigation controls")
    st.write("**Demo dataset** · synthetic only")
    if st.button("Initialize / refresh graph", use_container_width=True):
        try:
            seed_graph(); st.success("Synthetic entities and relationships loaded into FalkorDB." if graph else "Preview ready. Add FalkorDB credentials to persist graph data.")
        except Exception as e: st.error(str(e))
    target=st.selectbox("Investigate entity", options=[n['id'] for n in NODES], format_func=lambda x: next(n['name'] for n in NODES if n['id']==x), index=0)
    st.caption("All names, events and indicators are fictional demo data.")

if "investigation" not in st.session_state: st.session_state.investigation=None
if st.button("🔎 Investigate connected context", type="primary", use_container_width=True):
    if graph is not None:
        try: seed_graph()
        except Exception as e: st.warning(f"Seed warning: {e}")
    st.session_state.investigation=investigate(target)

if st.session_state.investigation:
    result=st.session_state.investigation
    entity=next(n for n in NODES if n['id']==target)
    neighbors=result['neighbors']
    # Transparent deterministic score: seed risk plus high-risk connected entities and graph breadth.
    high=sum(1 for n in neighbors if int(n.get('risk') or 0)>=80)
    breadth=min(len(neighbors),8)
    score=min(99,round(entity['risk']*0.55 + high*7 + breadth*2.5))
    action="ESCALATE + CONTAINMENT REVIEW" if score>=75 else "PRIORITIZE ANALYST REVIEW" if score>=50 else "MONITOR"
    a,b,c=st.columns(3); a.metric("Graph-derived risk",f"{score}/100", "High" if score>=75 else "Moderate" if score>=50 else "Low"); b.metric("Connected entities",len(neighbors)); c.metric("Risky neighbors",high)
    st.subheader("Agent decision")
    st.warning(f"**{action}** — risk score {score}/100. This is a recommendation for a human analyst, not an automatic production action.")
    reasons=[f"Target entity baseline risk: {entity['risk']}/100",f"{len(neighbors)} connected entities found through graph traversal",f"{high} connected entities have risk ≥ 80",f"Graph breadth contribution: {breadth} reachable entities (capped at 8)"]
    with st.expander("Why did the agent decide this?",expanded=True):
        for r in reasons: st.write("• "+r)
        st.caption("Scoring is deterministic and inspectable. It is a prototype heuristic, not a validated security model.")
    st.subheader("Connected evidence")
    if neighbors:
        st.dataframe([{"Entity":n.get('name'),"Type":n.get('kind'),"Risk":n.get('risk'),"Evidence":n.get('detail')} for n in neighbors],use_container_width=True,hide_index=True)
    else: st.info("No neighbors returned. Initialize the graph and investigate again.")
    st.subheader("Relationship paths")
    for p in result.get('paths',[])[:8]: st.code("  →  ".join(map(str,p)),language="text")
    st.caption("Evidence source: "+result['source'])
    if st.button("🧾 Save investigation decision to graph",use_container_width=True):
        try:
            log_decision(target,score,action,neighbors)
            st.success("Decision saved to FalkorDB." if graph else "Preview only: configure FalkorDB to persist decisions.")
        except Exception as e: st.error(f"Could not save decision: {e}")

with st.expander("Graph model & Cypher used"):
    st.markdown("**Nodes:** `Entity` (id, name, kind, risk, detail), `Decision` (target, score, action, evidence, created_at). **Relationships:** `RELATES_TO {kind}` with types such as `SEEN_ON`, `USED_BY`, `CAN_ACCESS`, `OBSERVED_IP`, and `INVOLVED_DEVICE`.")
    st.code("MATCH (t:Entity {id:$target})\nOPTIONAL MATCH p=(t)-[:RELATES_TO*1..4]-(n:Entity)\nRETURN t, collect(DISTINCT n), collect(DISTINCT p)",language="cypher")
    st.markdown("The traversal explores up to four hops and supplies the evidence used by the scoring and action recommendation. FalkorDB must be configured for graph-backed persistence; local preview is only for UI testing.")
with st.expander("Recent saved decisions"):
    decisions=read_decisions()
    if decisions: st.dataframe([{"Target":x[0],"Score":x[1],"Action":x[2],"Created":x[3]} for x in decisions],use_container_width=True,hide_index=True)
    else: st.caption("No saved graph decisions yet. Connect FalkorDB and save an investigation.")

st.divider()
st.caption("GraphSentinel AI · Graph Hacks: Agents That Act on Connected Data · Synthetic data only · AI-assisted prototype; verify before real-world use.")
