# GraphSentinel AI 🛡️

**Graph-powered, explainable threat investigation** for the WeMakeDevs × FalkorDB Graph Hacks — **Agents That Act on Connected Data** track.

GraphSentinel investigates synthetic security events by traversing relationships among IP addresses, devices, users, alerts, incidents, and services. Its risk score and recommended response are based on connected graph evidence, and an investigator can save decisions back to FalkorDB for later review.

> All entities and indicators in the included dataset are fictional. Recommendations are simulated and must not be used as a real security control.

## Why a graph?

A suspicious IP can be linked to a device, multiple accounts, an alert, and a critical service. The multi-hop Cypher traversal is part of the investigation itself—not just a graph visualization. The reachable entities and paths influence the risk calculation and recommended response.

## Architecture

- **UI:** Streamlit
- **Graph/context layer:** FalkorDB, queried with Cypher
- **Decision logic:** transparent deterministic risk heuristic based on target risk, high-risk neighbors, and graph breadth
- **Memory:** `Decision` nodes stored in FalkorDB
- **Dataset:** synthetic entities and relationships

## Graph data model

- `(:Entity {id, name, kind, risk, detail})`
- `(:Entity)-[:RELATES_TO {kind}]->(:Entity)`
- `(:Decision {id, target, score, action, evidence, created_at})`

Relationship kinds include `SEEN_ON`, `USED_BY`, `CAN_ACCESS`, `OBSERVED_IP`, `FLAGS_USER`, and `INVOLVED_DEVICE`.

## Run locally

Python 3.10+ recommended.

```bash
git clone https://github.com/YOUR_USERNAME/graphsentinel-ai.git
cd graphsentinel-ai
python -m venv .venv
# Windows: .venv\\Scripts\\activate
# macOS/Linux: source .venv/bin/activate
pip install -r requirements.txt
streamlit run app.py
```

The UI can be explored in local preview mode without credentials, but preview findings are **not persisted**. To satisfy the graph-backed behavior, connect to a FalkorDB instance and verify that the app reports `Connected to FalkorDB`.

## Connect FalkorDB

Set these environment variables in your shell or your deployment's secrets settings:

- `FALKORDB_HOST` — your FalkorDB endpoint hostname
- `FALKORDB_PORT` — usually `6379`, according to your provider's connection details
- `FALKORDB_PASSWORD` — password/token
- `FALKORDB_GRAPH` — graph name (default `graphsentinel`)
- `FALKORDB_SSL` — `true` for TLS endpoints

Never commit credentials. Use the endpoint/port/TLS details shown by your FalkorDB provider. Then click **Initialize / refresh graph**, investigate an entity, and save the decision. Confirm the saved decision appears under **Recent saved decisions**.

## Cypher traversal

```cypher
MATCH (t:Entity {id:$target})
OPTIONAL MATCH p=(t)-[:RELATES_TO*1..4]-(n:Entity)
WITH t,
     collect(DISTINCT {id:n.id,name:n.name,kind:n.kind,risk:n.risk,detail:n.detail}) AS neighbors,
     collect(DISTINCT [x IN nodes(p) | coalesce(x.name,x.id)]) AS paths
RETURN t.id, t.name, t.kind, t.risk, neighbors, paths
```

The traversal is capped at four hops to keep the investigation explainable and bounded. The score is a prototype heuristic—not a validated security model.

## Deploy on Streamlit Community Cloud

1. Create a **public GitHub repository** named `graphsentinel-ai` and push these files.
2. Open https://share.streamlit.io and choose **Create app**.
3. Select your repo, branch `main`, and entrypoint `app.py`.
4. In Advanced settings / Secrets, add your FalkorDB connection settings as environment secrets supported by Streamlit. For TOML secrets, use:

```toml
FALKORDB_HOST = "your-host"
FALKORDB_PORT = "6379"
FALKORDB_PASSWORD = "your-password"
FALKORDB_GRAPH = "graphsentinel"
FALKORDB_SSL = "true"
```

5. Deploy and wait for the app health check. Test an investigation and saved decision from the public URL. If cloud graph credentials are not ready, you may deploy the preview UI, but disclose that it is not graph-persistent.

## Demo video (required)

Record a 60–90 second screen capture:
1. Show the deployed app and connection status.
2. Initialize the graph.
3. Investigate `203.0.113.77` and show the multi-hop evidence and paths.
4. Explain how connected high-risk entities influence the score and recommendation.
5. Save the decision and show it in Recent saved decisions.
6. Briefly show the graph model and Cypher query.

## Track

**Agents That Act on Connected Data**

## AI assistance disclosure

This prototype was developed with AI coding assistance. The participant should test the app, understand the graph model and Cypher query, verify the scoring logic, and make meaningful changes before submission.

## Submission checklist

- [ ] Public GitHub repository
- [ ] README with setup instructions and graph data model
- [ ] Cypher query and explanation
- [ ] Live demo URL tested in a private/incognito window
- [ ] Demo video URL
- [ ] Correct track selected in submission form
- [ ] FalkorDB connection verified; no secrets committed
