# Laocoon

A security layer for LLM agents. Laocoon runs as an OpenAI-compatible proxy between an application and its LLM.
The application keeps running its own tools. Laocoon decides which tools the model sees and which of the model's
tool calls ever reach the application.

The only change the application needs is to point its LLM base URL at the proxy.

The core rule: deterministic code makes the decisions. The AI classifier can only make a decision stricter, never
looser.

The demo protects [Athena eClass](https://github.com/StefanosChaliasos/llm-hackathon-26), the hackathon's university
LMS, without changing its code. eClass is only the demo: Laocoon works with any app whose agent uses an
OpenAI-compatible API, configured through a policy file.

## Mitigations

| # | Name | What it does |
|---|---|---|
| ① | Deputy Firewall | The model sees only the tools the user's role allows. Identity arguments are filled in by code, and every reference (a course, an assignment) is checked against the user's scope. |
| ② | Siren Guard | A prompt-injection classifier at four checkpoints: the user's message (G1), tool results (G2), before a sensitive action (G2b) and the answer (G3). Backends: TypeSafe Jev, any OpenAI-compatible model as a judge, a local Hugging Face model, or Jev and a local model together. Off unless configured. |
| ③ | Canary | A secret marker per conversation in the system prompt, and decoy "honey" records in the data. If either appears in an answer or a tool argument, it is treated as a leak and the conversation is stopped. |
| ④ | Bound approvals | Sensitive actions wait for a human approval that is cryptographically bound to the exact arguments and can be used once. |
| ⑤ | Audit & control | A tamper-evident (hash-chained) audit log, a kill switch and an operator console. |
| ⑥ | Attack memory | Optional. Attacks confirmed by a tripwire or a person are remembered, so repeats and variants are caught earlier. |

Also available:

- **Private data:** declared personal data (for example AMKA, IBAN, phone numbers) is replaced with placeholders
  before it reaches the LLM or the classifier. Only Laocoon maps them back, and only where the policy allows.
- **Plan commitment** (optional, `LAOCOON_PLANNER=openai`): before the agent reads any data, a separate LLM call
  that sees only the user's own messages decides which write actions the request needs. Actions outside that plan
  are sent for approval or denied.

## Where permission data comes from

Set with `LAOCOON_AUTHZ_SOURCE`:

| Mode | How Laocoon learns facts such as "who teaches this course" |
|---|---|
| `db` (default) | A read-only connection to the app's database |
| `views` | A database login that can read only a few views (SQLite or PostgreSQL) |
| `lookup` | No database: facts come from the results of the app's own read tools |
| `authzen` | The customer's authorization service, over OpenID AuthZEN 1.0 (`LAOCOON_AUTHZEN_PDP`). A reference service is included: `python -m laocoon.authzen_pdp` |

## Running the demo

Both ways expect the original eClass checked out next to this repository, at `../eclass-original`.

### Locally (no Docker)

```bash
scripts/run_local.sh --mock     # offline, with a scripted demo model
scripts/run_local.sh            # with a real LLM: put AI_STUDIO_API_KEY in .env
scripts/run_local.sh stop
```

The script creates a virtual environment at `../.venv` and clones eClass into `../eclass-original` if it is
missing. The offline model only answers the exact prompts in `eval/scenarios/*.yaml`.

- eClass, protected: http://localhost:8081
- Laocoon console: http://localhost:9000/laocoon

### With Docker

```bash
cp deploy/.env.example deploy/.env      # set AI_STUDIO_API_KEY and LAOCOON_SECRET
docker compose -f deploy/docker-compose.proxy.yml --env-file deploy/.env up --build
```

- eClass, protected: http://localhost:8081
- Laocoon console: http://localhost:9000/laocoon

`LAOCOON_SECRET` must be a random value of at least 32 characters, for example `openssl rand -hex 24`.

### Console

The console has the live events, pending approvals, the kill switch, a settings page that turns single
mitigations on or off while the proxy runs, and a policy studio with a visual and a YAML editor. Sign in with an
account from `LAOCOON_CONSOLE_USERS`; when it is empty, the demo account is `admin` / `laocoon`.

## Policies

Everything app-specific is in a policy YAML file. The eClass policy is `policies/eclass.yaml`.

- [policies/README.md](policies/README.md): a step-by-step guide to writing a policy
- [policies/SPEC.md](policies/SPEC.md): the full reference

## Tests and evaluation

```bash
pip install -r requirements-dev.txt
python -m pytest
```

The tests use the eClass seed data, so they also expect `../eclass-original`.

The evaluation runs attack and benign scenarios against eClass, with and without Laocoon:

```bash
python -m eval.run --target proxy --mode both --llm mock
```

Results are written to `eval/results/`, which is not committed.

## Layout

| Path | Contents |
|---|---|
| `laocoon/` | The proxy and all mitigations |
| `policies/` | The eClass policy, the AgentDojo benchmark policies, and the policy docs |
| `tests/` | Tests |
| `eval/` | Evaluation harness, scenarios, attack payloads and the offline mock LLM |
| `deploy/` | Docker, systemd and deploy scripts |
| `scripts/` | Local demo and benchmark scripts |
| `brand/` | Logo |
