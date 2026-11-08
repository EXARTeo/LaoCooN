# Laocoon policy format, version 2: reference

This is the complete reference for a Laocoon policy file. For a walk-through (how to write one for your
application, review the database script, and go live), read the [guide](README.md) first.

One YAML file describes everything Laocoon enforces for your application:
- which tools each role may use, on which objects, and which arguments are filled in by Laocoon instead of the model;
- which actions wait for the user's explicit approval;
- what personal data the model must never see;
- how the guardrail classifier reacts at each checkpoint;
- what Laocoon may read of your database, from which the SQL views your database administrator installs are
  generated (`data_model`);
- or, instead, which questions Laocoon asks your own authorization service over OpenID AuthZEN, whatever store it
  sits on (`authzen`, §12).

The words **must**, **must not** and **may** are used in their usual normative sense.

---

## 1. File and conventions

| Rule | Value |
|---|---|
| Format | YAML, UTF-8, loaded safely (no custom tags) |
| Size | at most 256 KiB when edited in the studio |
| Top level | a mapping; the keys in §3 |
| Unknown keys | a **warning**, and the key is ignored |
| Default | everything not listed is denied (`default: deny` is the only value accepted) |

**Names**

| What | Pattern | Example |
|---|---|---|
| roles, tools, classifier classes | `[A-Za-z_][A-Za-z0-9_.-]{0,63}` | `teacher`, `grade_submission` |
| `data_model` kinds, relations, fields, constraints, previews | `[a-z][a-z0-9_]{0,40}` | `course`, `attempted_by` |
| your database's tables and columns (in `data_model` only) | `[A-Za-z_][A-Za-z0-9_]{0,62}` | `enrollments`, `teacher_id` |
| private-data classes | `[A-Za-z][A-Za-z0-9_]{0,31}` | `AMKA` |

Table and column names are checked against their pattern and quoted in the generated SQL, so nothing written in
the policy can change the meaning of the script.

**Validation.** The policy studio checks the file and reports issues at three levels:
- **error:** the draft cannot be saved;
- **warning:** saved, but probably not what you meant;
- **info:** for your attention.

A saved draft is not live. A policy becomes active only when your Laocoon operator deploys it, so a session in the
studio can never change what is enforced.

**Arguments.** Tool arguments are named exactly as in the tool declarations your application sends to the model
(the JSON schema `properties`).

---

## 2. How a tool call is decided

The policy is applied in this order. The first step that objects decides.

**Before the model is called**
1. **The tool set of the run.** It contains only the tools whose `allow` grants the caller's role, narrowed further
   by the client's per-run choices (it can only narrow). Every other tool is removed from the request: the model
   never learns it exists.
2. **Bound arguments** (`bind`) are removed from the tools' schemas.
3. **Scope enums.** Where the role's rule for an argument is a single constraint with a closed answer, the allowed
   values (for example the codes of the user's courses) are added as an `enum` (§5.4, `enum`).

**For each tool call the model makes**
1. **Role.** No rule for the caller's role → deny (`rbac`, severity high).
2. **Forbidden arguments.** An argument in `deny_args` with a value → deny (`identity`, high).
3. **References.** Every argument listed in `refs` is resolved to an object id **once**, and the tool runs with
   that id. Not found, or more than one match → deny (`abac`, low).
4. **Bound arguments.** Missing → filled with the caller's id. Present and pointing at anyone else → deny
   (`identity`, high).
5. **Constraints.** Every argument named in the role's rule must be present (missing → deny, medium) and must
   satisfy its constraint (otherwise deny, `abac`, high).
6. **Fields.** When the rule has `fields`, any other non-empty argument → deny (`abac`, high).
7. **Approval.** If the merged approval setting (§6) asks, the call is held. The user sees a card with the exact
   arguments and approves it by typing `approve ap_…` (or `έγκριση ap_…`). The approval is bound to those
   arguments, single-use and time-limited.
   - The classifier (G2b) and private-data rules (§8) may also require an approval, never remove one.
8. **Result.** The role's `filter`s run on the result. Then `untrusted_output` marks third-party content, which
   the classifier checks (G2) before the model reads it.

**Answers.** Before the user sees an answer, Laocoon checks it for:
- the conversation's canary;
- honey values (§7.3);
- matches of `secret_patterns`;
- verbatim copies of the system prompt;
- the classifier (G3).

**Repeated denials.** Denials of severity high count against the user. By default, 5 within 10 minutes freeze the
user's assistant for 15 minutes; your operator sets these numbers. Medium and low denials never count, so an
outage or a typo cannot freeze anyone.

Your operator can switch individual mitigations off at run time from the console. Every such change is audited.
The policy describes the configured behaviour.

---

## 3. Top-level keys

| Key | Type | Required | Section |
|---|---|---|---|
| `version` | `2` | no (default 2) | §4.1 |
| `app` | string | no | §4.1 |
| `default` | `deny` | no | §4.1 |
| `roles` | list of names | recommended | §4.1 |
| `tools` | mapping tool → spec | yes | §4.2 |
| `refs` | mapping argument → kind | when tools take references | §5.1 |
| `data_model` | mapping | with `LAOCOON_AUTHZ_SOURCE=views` | §5 |
| `authzen` | mapping | with `LAOCOON_AUTHZ_SOURCE=authzen` | §12 |
| `approvals` | mapping | no | §6 |
| `sensitive_fields` | list of field names | no | §7.1 |
| `secret_patterns` | list of regexes | no | §7.2 |
| `honey_records` | mapping | no | §7.3 |
| `private_data` | mapping | no | §8 |
| `guard` | mapping | no | §9 |
| `identity`, `lookups`, `ref_fallback` | mappings | only with `LAOCOON_AUTHZ_SOURCE=lookup` | §10 |

---

## 4. Roles and tools

### 4.1 `version`, `app`, `default`, `roles`

```yaml
version: 2
app: acme-helpdesk          # a label for the console and the audit log
default: deny
roles: [customer, agent, admin]
```

- `roles` lists the values of the caller's role as your application reports it. A role used elsewhere in the
  policy but not listed is a warning. Without `roles`, the roles are taken from the `allow` rules (a warning). A
  duplicate is an error.

### 4.2 `tools.<name>`

One entry per tool your application declares. A tool that is not listed is denied to everyone and never shown to
the model.

| Key | Type | Default | Meaning |
|---|---|---|---|
| `effect` | `read` \| `write` \| `communicate` \| `external` | `read` (warning) | What the tool does. Anything but `read` is a **side effect**. |
| `allow` | mapping role → rule | `{}` | Who may call it, and on what (§4.3). |
| `bind` | mapping role → list of arguments | none | Arguments that **are** the caller: hidden from the model and filled by Laocoon (§4.4). |
| `deny_args` | list of arguments | none | Arguments that must stay empty (for example an "on behalf of" field). |
| `filter` | mapping role → list of filter names | none | Applied to the result before the model sees it (§4.5). |
| `untrusted_output` | mapping, or a name | none | The result contains content written by other people (§4.6). |
| `approval` | bool | from `approvals.defaults` | Overrides the effect's default (§6). |
| `locked` | bool | `false` | The approval is always required; no role setting or user choice can clear it. |
| `scope_enum` | bool | `true` | `false`: do not offer the user's scope as an enum for this tool. |

`effect: external` is a warning: it is a channel to third parties. A side effect that runs without approval for
some role is also a warning.

### 4.3 `allow`

```yaml
allow:
  customer: {ticket_id: [own_ticket, open]}          # all of
  agent:    {ticket_id: "team_ticket|assigned_ticket"} # any of
  admin:    true                                      # full access
```

| Rule | Meaning |
|---|---|
| `true` | the role may call the tool with any arguments (bound arguments and approvals still apply) |
| `false`, absent, `{}` | no access (`{}` is a warning: write `true` for full access) |
| mapping | each key is an argument, and its value is a **constraint expression** the argument's value must satisfy |
| `fields: [...]` (inside the mapping) | the only other arguments that may have a value (for example the profile fields a user may change) |

**Constraint expression**
- `name`: one constraint;
- `"a|b"`: any of them;
- `[a, b]`: all of them. A list must not contain `|`.

Names are the constraints of `data_model.constraints` (§5.4), the built-in `self` (the value is the caller's own
id), and any value constraints your deployment provides (the studio lists them; Athena eClass has
`read_only_sql`). An unknown name is an error.

The constraint receives the argument's value **after** reference resolution (§5.1), so it always sees an id.

### 4.4 `bind`

```yaml
list_my_tickets:
  bind: {customer: [customer_ref]}
```

- **For the model:** the argument disappears from the tool's schema.
- **In a call:** missing → Laocoon fills in the caller's id; present → it must be the caller (it is resolved as a
  user reference first); anyone else → deny, high.

Use it for every argument that names "the current user": the owner of a submission, the sender of a message, the
user whose grades are read.

### 4.5 `filter`

Filters minimise what the model reads. Examples: drop the password hash, keep only the user's own rows, keep only
published grades. They are named functions your Laocoon deployment provides for your application, and the studio
lists the available names. An unknown name is an error.

To remove or pseudonymise personal **fields**, use `private_data` (§8) instead. It needs no deployment support.

### 4.6 `untrusted_output`

The result contains text other people wrote (forum posts, comments, messages). Laocoon then:
- records who wrote each item;
- has the classifier check it (G2) before the model reads it;
- quarantines items the classifier flags;
- checks every side effect proposed after it was read (G2b). Such a call waits for approval when the classifier
  is unsure, fails or is switched off.

```yaml
untrusted_output: {author_field: author, ref: comment, id_field: id}
```

| Key | Default | Meaning |
|---|---|---|
| `author_field` | required | the field of each result row that holds the author (username or user id) |
| `ref` | the tool's name | the kind of item, used in the audit log (`comment:17`) |
| `id_field` | `id` | the field holding the item's id |

Content the caller wrote themselves is not treated as untrusted. A deployment may also provide named kinds (Athena
eClass: `course_teacher`, where the author is the teacher of the course).

---

## 5. References and the data model

### 5.1 `refs`

```yaml
refs:
  ticket_id: ticket
  assignee_ref: user
```

For **every** tool, an argument whose name appears here is a reference to an object of that kind.
- A number is an id, and it must exist.
- Text is resolved by the kind's `refs` tiers (§5.3).
- One match → the tool runs with its id. None, or more than one → deny (low).

Ambiguity is never resolved by picking one. In `views` mode, kinds must be objects of `data_model`.

### 5.2 `data_model`

`data_model` says what Laocoon may read of your database, and what each constraint name means in terms of it.
It is the only part of the policy that names your tables. From it, Laocoon generates the SQL script your database
administrator installs (§11). At run time, Laocoon reads only those views.

```yaml
data_model:
  principal: user        # the kind of the logged-in user (default: user)
  objects: {...}         # §5.3   → one view per object kind
  relations: {...}       # §5.4   → one view per relation
  constraints: {...}     # §5.5   meanings of the names used in allow
  derive: {...}          # §5.6
  previews: {...}        # §5.7   optional, personal data
```

Unknown keys in `data_model` itself, in an object and in a relation are errors, unlike the rest of the policy:
a typo there would change what is read.

### 5.3 `objects.<kind>`

```yaml
objects:
  user:   {table: accounts, fields: {username: login, name: display_name, role: role},
           refs: [{username: exact, name: iexact}, {name: contains}], label: "{name} ({username})"}
  team:   {table: teams, fields: {name: name}, enum: name, refs: [{name: iexact}], label: "{name}"}
  ticket: {table: tickets, fields: {closed: is_closed}}
```

| Key | Type | Default | Meaning |
|---|---|---|---|
| `table` | table name | required | where the objects of this kind are stored |
| `id` | column | `id` | the column holding the object's id (an integer) |
| `fields` | mapping field → column | `{}` | the columns Laocoon may read, under the name used in the policy |
| `refs` | list of tiers | none (ids only) | how a reference by name is resolved |
| `label` | format string | none | how the object is shown on approval cards, from its fields: `"{code} {title}"` |
| `enum` | a field | none | the field offered to the model as the allowed values of a scoped argument |

**Fields are names, codes and state, never personal data.** A column listed in `sensitive_fields` is an error here.
The principal kind must have the fields `username` and `role`. A field `name`, if present, is the user's display
name.

**Reference tiers.** A reference that consists of digits only is an id. Otherwise the tiers are tried in order:
- each tier is a mapping field → match, and a row matches the tier if **any** of its fields matches;
- exactly one matching row → resolved;
- two or more → **not resolved** (deny);
- none → the next tier;
- after the last tier, not found (deny).

A kind without `refs` accepts ids only (`"6"`, `"6.0"`).

| Match | True when |
|---|---|
| `exact` | the field equals the reference (case-sensitive) |
| `iexact` | they are equal ignoring case |
| `contains` | the field contains the reference, ignoring case; `%` and `_` in the reference are taken literally |
| `upper_nospace` | the field equals the reference upper-cased with spaces removed (codes: `cs 101` → `CS101`) |

**`enum`.** The allowed values are offered to the model when all of these hold:
- the role's rule for an argument is exactly **one** constraint;
- that constraint is a single path from this kind to the user (§5.5);
- the tool does not say `scope_enum: false`.

The model then sees, for example, `Allowed: Billing, Network`. At most 50 values are offered. The constraint is
still checked on every call.

### 5.4 `relations.<kind>.<name>`

```yaml
relations:
  team.member:     {table: team_members, from: team_id, to: account_id, target: user}
  user.teams:      {reverse: team.member}
  ticket.customer: {table: tickets, from: id, to: customer_id, target: user}
```

| Key | Meaning |
|---|---|
| `table` | the table holding the pairs: the object's own table (a foreign key) or a link table |
| `from` | the column with the id of the `<kind>` object |
| `to` | the column with the id of the related object (a NULL means "no relation") |
| `target` | the kind of the related object |
| `reverse: <kind>.<name>` | the same relation read the other way. It gets no view of its own, and its target is the other relation's kind. Only `reverse` may be given. |

A relation must not be named after its own kind. Relations may be one-to-many or many-to-many.

### 5.5 `constraints.<name>`

```yaml
constraints:
  own_ticket:      ticket.customer
  team_ticket:     ticket.team.member
  teammate:        user.teams.member
  open:            not ticket.closed
  open_team:       [ticket.team.member, not ticket.closed]    # all of
```

**Grammar**

```
constraint  = path | "[" path { "," path } "]"            list: all must hold
path        = [ "not " ] kind { "." relation } [ "." field ]
```

**Meaning.** A path starts at the object the argument refers to, whose kind must match the path's first word. It
follows each relation in turn, and it ends in one of two ways:
- **at the principal kind**, after at least one relation: true when the caller is reached, whatever route the
  relations take;
- **at a field**, which may only be the last step: true when that field is set (non-zero, non-empty, true) for an
  object reached.

`not` negates the path.

> **A `not` path is true when nothing matches, including when the object does not exist.** `open: not ticket.closed`
> holds for ticket 999 even if there is no ticket 999. Always combine a `not` path with a positive one in a list
> (`[team_ticket, open]`), as every rule in the examples does.

- `self` is built in and reserved: a constraint defined here under that name is ignored.
- "Any of" is written in the tool's rule (`"a|b"`), not here.
- A constraint used in `tools` but not defined here is reported (§5.8).

### 5.6 `derive.<name>`

```yaml
derive:
  ticket_owner: {arg: ticket_id, path: ticket.customer}
```

`derive` gives a value derived from an argument by following relations: no `not`, no field, at least one relation.
Your deployment uses it for features that need, for example, "the owner of this object". Define one only when
your deployment's documentation asks for it.

### 5.7 `previews.<name>` (optional, personal data)

```yaml
previews:
  final_grade: {table: final_grades, key: {course: course_id, student: student_id}, value: grade}
```

`previews` are the values **before** a change, shown on approval cards ("grade 7.5 → 9"). They are personal data,
so:
- the generated script includes them only when asked to (`--previews`);
- without them the cards show "—", and nothing else changes.

Each preview becomes a view with one column per key and a column `value`. Define one only for the approval cards
your deployment shows.

### 5.8 What the studio checks in `data_model`

| Check | Level |
|---|---|
| shapes, names and keys (§5.3–5.7); a path that names a missing kind, relation or field; a field that is not the last step; a constraint path that ends at neither the principal nor a field | error |
| a view would read a column listed in `sensitive_fields` | error |
| `previews` present | info (personal data) |
| a constraint used in `tools` but not defined here | warning |

---

## 6. `approvals`

```yaml
approvals:
  defaults: {read: false, write: true, communicate: true, external: true}   # these are the defaults
  roles:
    admin: {post_announcement: false}        # admins post announcements without a card
```

Whether a call waits for approval is decided in layers; each later layer that says something wins:

1. `approvals.defaults[effect]`
2. the tool's `approval`
3. `approvals.roles[role][tool]`
4. the user's per-run choice, sent by your client (it may only add or clear gates that are not locked)
5. `locked: true`: always asks, overriding everything above

| Check | Level |
|---|---|
| a default of `false` for a side effect | warning |
| `locked: true` with `approval: false` | warning (locked wins) |
| a tool in `approvals.roles` that is not in `tools` | warning |
| a value that is not `true`/`false` | error |

---

## 7. Leak protection

### 7.1 `sensitive_fields`

```yaml
sensitive_fields: [password_hash, email, phone]
```

- Argument names whose values are masked in the audit log.
- Columns the `data_model` must never read (an error, §5.8).

### 7.2 `secret_patterns`

```yaml
secret_patterns: ['FLAG\{[^}]+\}']
```

Regular expressions searched for in your system prompt. If an answer contains one of the matches, the answer is
withdrawn and the event is logged (severity high). An invalid expression is an error.

### 7.3 `honey_records`

```yaml
honey_records:
  values: ["13579135791"]       # decoy values your operator plants in the application's data
  visible_to: [admin]           # roles that may legitimately see them
```

| Where a honey value appears | Outcome |
|---|---|
| in an answer to a role not in `visible_to` | the answer is withdrawn |
| in an answer to a role in `visible_to` | flagged only |
| in the arguments of a tool call | **kill**: the run is stopped for an hour and the conversation is flagged for your operator |

With `private_data`, every honey value must match one of its classes' patterns. Otherwise it would reach the model
as the only real-looking value and stand out (a warning).

---

## 8. `private_data`

Declared personal data never reaches the model or the classifier. Each value becomes a placeholder `⟦TYPE:id⟧`
that is stable within a conversation. Only Laocoon maps it back:
- **in answers:** a value the role was allowed to see (`answer`);
- **in tool arguments:** by a fixed decision table (`tool_args`). For example, a value read from untrusted
  content that goes into a side effect always needs a locked approval, and personal data sent to a third party
  after untrusted content was read is denied.

Your operator must set a random server secret of at least 32 characters.

```yaml
private_data:
  id_length: 6
  subject_args: {send_message: to, update_user: user_ref}
  classes:
    AMKA:  {pattern: '(?<!\w)\d{6}[ -]?\d{5}(?!\w)', validate: date_ddmmyy, fields: [amka],
            normalise: "digits:11", dummy: "00000000000"}
    EMAIL: {pattern: '...', fields: [email], normalise: casefold}
    NOTES: {fields: [admin_notes], match: field, answer: {admin: shown, "*": never}}
    PASSWORD_HASH: {fields: [password_hash], action: drop}
```

| Key | Type | Default | Meaning |
|---|---|---|---|
| `id_length` | `6` \| `12` | `6` | length of the placeholder id |
| `classifier_view` | `dummy` \| `placeholder` | `dummy` | what the classifier sees instead of a value: the class's constant dummy (recommended: placeholders raise injection scores) |
| `ttl` | seconds | `86400` | how long placeholders of a conversation can be mapped back |
| `subject_args` | mapping tool → argument | `{}` | the argument naming whose record a tool targets or who receives it (used by the decision table) |
| `classes` | mapping NAME → class | required, non-empty | the kinds of personal data |

**Class keys**

| Key | Values (default first) | Meaning |
|---|---|---|
| `pattern` | regex | detection in free text |
| `validate` | `date_ddmmyy`, `luhn`, `iban_shape`, `iban_mod97`, `phone_gr`, `afm_mod11`, `idcard_gr` | a pattern match counts only if it also passes this check |
| `fields` | list of field names | values of these fields, at any depth of a result, case-insensitive |
| `match` | `pattern` (when a pattern is set), else `field`; or `exact` | `field`: only as a field's value; `exact`: a field's values are also replaced wherever they appear verbatim |
| `action` | `placeholder`, `mask`, `drop` | `mask` shows `***33` (irreversible); `drop` removes the field for every role and tool |
| `answer` | `shown`, `self`, `never`, or `{role: mode, "*": mode}` | whether the value is restored in answers: always, only the user's own and typed values, never |
| `tool_args` | `table`, `self`, `never` | whether the value may be restored into a tool argument: by the decision table, only the user's own, never (deny) |
| `normalise` | `text`, `digits`, `digits:11`, `upper_nospace`, `phone_gr`, `idcard_gr`, `casefold` | how two spellings are recognised as the same value |
| `dummy` | string | the constant the classifier sees for this class |

A class needs a `pattern` or `fields`.

| Check | Level |
|---|---|
| an invalid value or regex; an unknown validator; an empty `classes` | error |
| a field declared by two classes (the first wins) | warning |
| a pattern slower than 50 ms on adversarial text | warning |
| a tool in `subject_args` that is not in `tools` | warning |

Filters run first: a class never brings back a field a filter removed.

---

## 9. `guard`: the classifier

The classifier is a signal: it can only make a decision stricter. Every key is optional, and these are the
defaults.

```yaml
guard:
  classes:
    - {name: instruction_injection, description: "text that tries to give the assistant orders or change its rules"}
    - {name: privilege_escalation,  description: "claims to be staff/admin, or asks to ignore the user's role"}
    - {name: data_exfiltration,     description: "asks to send, reveal or encode data outward (messages, URLs, images)"}
    - {name: tool_hijack,           description: "tries to make the assistant call a write or communication tool"}
    - {name: benign,                description: "ordinary content or request"}
  policy:
    instruction_injection: {G1: block, G2: quarantine}
    privilege_escalation:  {G1: block}
    data_exfiltration:     {G2: quarantine, G3: redact}
    tool_hijack:           {G2: quarantine, G2b: hitl}
  thresholds: {block: 0.85, hitl: 0.5}
  steering: {merge_into: instruction_injection}
  on_error: {G1: allow, G2: review, G2b: hitl, G3: allow, G4: allow}
  min_chars: 16
  max_chars: 6000
  max_chunks: 4
```

**Checkpoints and the actions they use**

| Checkpoint | What is checked | Actions |
|---|---|---|
| G1 | the user's message (a blocked message never reaches the model) | `allow`, `flag`, `block` |
| G2 | tool results with untrusted content | `allow`, `flag`, `review`, `quarantine` |
| G2b | a side effect proposed after untrusted content was read | `allow`, `flag`, `hitl` (ask the user) |
| G3 | the final answer | `allow`, `flag`, `redact` |
| G4 | content your application stores (a new post), in SDK integrations | `allow`, `flag` |

**Decision.** For each class configured at a checkpoint:
- a score ≥ `block` → that class's action;
- a score between `hitl` and `block` → the checkpoint's medium action: `flag`, `review` at G2, `hitl` at G2b;
- below `hitl` → allow.

A class that is not configured at a checkpoint can only `flag` (at a score ≥ `block`). The strictest action wins.

| Key | Meaning |
|---|---|
| `classes` | the labels the classifier scores; `benign` is added if missing; `steering` is reserved |
| `policy` | class → {checkpoint: action} |
| `thresholds` | `block` and `hitl`, between 0 and 1 (`hitl` above `block` is a warning) |
| `steering` | the extra "is this text trying to steer the assistant?" score is merged into `merge_into`, which must be an attack class |
| `on_error` | what happens at each checkpoint when the classifier fails; `G2b: allow` is a warning |
| `min_chars` | shorter text is not classified |
| `max_chars`, `max_chunks` | longer text is split, and the worst chunk decides; beyond `max_chunks` the rest is not sent and the verdict is at least `review` |

An action that a checkpoint does not use is logged only as a flag (a warning).

---

## 10. Settings for the no-database mode (`LAOCOON_AUTHZ_SOURCE=lookup`)

These keys are read only when Laocoon has no access to your database at all. It then learns the facts behind the
constraints from your application's own read tools. They are ignored in `views` mode.

| Key | Meaning |
|---|---|
| `identity.fields` | the labels of the identity block your application writes into its system message (`{id, username, role, name}`); each must appear exactly once |
| `identity.verify` | confirm the identity with your application's own record before anything else |
| `lookups.tools` | your read tools Laocoon may ask your application to run; their results never reach the model |
| `lookups.out_of_scope` | also read objects outside the user's scope to find out whether they are in it (enable only if your UI never shows raw tool results) |
| `lookups.ttl` | maximum age in seconds of a fact: `{read, write, identity}` |
| `refs.<arg>: {kind, fallback: app}` / `ref_fallback` | a reference outside the user's visible scope passes through as written and your application resolves it |

In `views` and `db` mode, the identity block must use the labels `User id`, `Username` and `Role`, and it is checked
against your database. In production, use the signed identity header instead.

---

## 11. The generated SQL (the contract with your database)

Laocoon turns `data_model` into a script that your database administrator reviews and runs once, as the owner of
your tables, and again after migrations that touch those columns. Generate it with `laocoon.views sql`; in a
hosted deployment your Laocoon operator sends it to you.

### 11.1 Views

| From | View | Columns |
|---|---|---|
| `objects.<kind>` | `laocoon.obj_<kind>` | `id`, then each field under its policy name |
| `relations.<kind>.<name>` (not `reverse`) | `laocoon.rel_<kind>_<name>` | `<kind>_id`, `<name>_id` |
| `previews.<name>` (only with `--previews`) | `laocoon.prev_<name>` | `<key>_id` for each key, `value` |

Every view is a projection of **one** table: listed columns, no joins, no conditions. Joins happen in Laocoon's
queries over the views, which you can see in your database's statement log.

### 11.2 PostgreSQL (the database enforces the limit)

The script, in one transaction:
1. creates schema `laocoon` if missing;
2. drops and recreates each view;
3. creates role `laocoon` (`LOGIN`, **no password in the script**: set it with `\password laocoon`);
4. `ALTER ROLE laocoon SET default_transaction_read_only = on` and `SET statement_timeout = '2s'`;
5. revokes everything in schema `laocoon` from the role (views of an older policy lose their grant);
6. `GRANT USAGE ON SCHEMA laocoon`, then `GRANT SELECT` on each view, **by name**.

It grants nothing on your own schema. The views read with their owner's rights (PostgreSQL's default; keep
`security_invoker` off), which is what lets a login that cannot read your tables read the views.

**Stricter variant** (`--functions`). The role gets `EXECUTE` on yes/no functions instead of `SELECT` on the
relation views:
- `can_<constraint>(object, user)`;
- `scope_<constraint>(user)`, the user's own scope, which the scope enums and some filters need;
- `derive_<name>(object)`.

Every function is `SECURITY DEFINER` with `search_path = pg_catalog, pg_temp`, and `EXECUTE` is revoked from
`PUBLIC`. Features that need to follow relations directly then degrade: attributing course content to its
teacher, and some lines of approval cards.

**Migrations.** A view that depends on a column blocks `ALTER COLUMN … TYPE` on it, and a plain `DROP TABLE` of a
table it reads. Renaming a column, or dropping one the views do not use, works.
- **Order:** `DROP SCHEMA laocoon CASCADE`, migrate, re-run the script.
- **Meanwhile:** Laocoon fails closed. Constraint checks are denied at severity medium; nobody is frozen.

### 11.3 MySQL / MariaDB

The script uses `CREATE OR REPLACE SQL SECURITY DEFINER VIEW` in a database `laocoon`, and it needs the name of
your application's database (`--app-schema`). A view there does not block migrations: it fails when queried, and
Laocoon then fails closed. *Laocoon's MySQL connection is not available yet; the script can be reviewed today.*

### 11.4 SQLite

SQLite has no permissions. Two options:
- **Self-imposed.** Laocoon opens the file read-only, creates the views as temporary views in its own connection
  (your file is not modified), and refuses every read that is not made through them. This is Laocoon restraining
  itself; it is not enforced by the database.
- **Export.** A job on your side copies the views' rows into a separate file every few seconds
  (`laocoon.views export`), and Laocoon gets only that file. This is a real boundary, stale by the copy interval.

### 11.5 What Laocoon relies on

At run time Laocoon relies only on the views' **names and columns**. `laocoon.views check` compares what the login
can read with what the policy needs, view by view.

On PostgreSQL and MySQL you may adapt a view's body, for example to exclude archived rows, as long as its name
and columns stay the same. The check does not compare bodies, and a wrong body gives wrong decisions in your own
application, so review such changes as carefully as the policy itself. On SQLite, Laocoon creates the views itself
from the policy.

---

## 12. `authzen`: asking your own policy decision point

With `LAOCOON_AUTHZ_SOURCE=authzen`, Laocoon has no access to your data at all. It is an **enforcement point**
(PEP) in the sense of the OpenID **AuthZEN Authorization API 1.0**, and asks your **policy decision point** (PDP)
every question its rules raise. The PDP can sit on anything: SQL, a document store, a graph, a directory, another
service. Laocoon receives decisions, never data.

Laocoon keeps its own rules (§2: roles, bound arguments, `fields`, approvals). The PDP answers the constraints and
supplies the scope. This section maps Laocoon's names to your PDP's.

### 12.1 The mapping

```yaml
authzen:
  subject: user                          # the AuthZEN subject type of the logged-in user
  identity: {action: identity}           # the PDP confirms the identity block (12.3)
  resources:
    user:   {type: user, search: directory, refs: [{username: exact, name: iexact}, {name: contains}],
             label: "{name} ({username})"}
    ticket: {type: ticket, id: string, search: view}   # tickets in a document store
  constraints:
    own_ticket:  {resource: ticket, action: read_own}
    team_ticket: {resource: ticket, action: work_on}
    teammate:    {resource: user,   action: teammate}
  relations:
    ticket.assignee: {action: assigned}  # the users with `assigned` on a ticket
    ticket.customer: {action: read_own}
  derive:
    ticket_owner: {arg: ticket_id, relation: ticket.customer}
```

| Key | Meaning |
|---|---|
| `subject` | the subject type Laocoon sends for the logged-in user (default `user`) |
| `identity.action` | the action that confirms the identity block. Required with system-message identity; without it, use the signed identity header. |
| `resources.<kind>.type` | your PDP's resource type for that kind (default: the kind's name) |
| `resources.<kind>.id` | `int` (default) or `string`, for stores whose ids are not numbers. **Users must have integer ids.** |
| `resources.<kind>.search` | the action whose resource search lists what the user may refer to. Needed for references by name, and to confirm that an id exists. Without it, an id goes to the constraints as written. A role whose rule is `true` then sends it to the tool unchecked, and the studio warns about each such tool and role. A PDP with many objects should use the reference hint (12.2) to answer with just the one asked for. |
| `resources.<kind>.refs`, `label`, `enum` | as in §5.3, over the `properties` of the search results |
| `constraints.<name>` | `{resource: kind, action}`: one evaluation per check. `action` defaults to the constraint's name. Every constraint the tools use needs an entry (a warning otherwise). |
| `relations.<kind>.<name>` | `{action}`: the users that have this action on an object (a subject search), for attribution and approval cards. `action` defaults to the key. |
| `derive.<name>` | `{arg, relation}`: a single user reached through a relation |

Unknown keys in `authzen`, and in its resources, are errors. Types and actions must match
`[A-Za-z0-9_.:/@-]{1,128}`.

### 12.2 What Laocoon sends, and what it expects

All requests are `POST` with a JSON body, as AuthZEN 1.0 specifies.

| Question | Request |
|---|---|
| a constraint | **Access Evaluation**: `subject {type, id, properties: {username, role}}`, `action {name}`, `resource {type, id}` |
| several constraints that must all hold | **Access Evaluations** with `options.evaluations_semantic: deny_on_first_deny`, when your metadata lists that endpoint; otherwise one evaluation at a time |
| the user's scope (enums, scope filters) | **Resource Search**: `subject`, `action` = the constraint's action, `resource {type}` |
| a reference by name, a label | **Resource Search** with the kind's `search` action and `context: {"laocoon": {"reference": "<text>"}}` |
| who stands in a relation | **Subject Search**: `subject {type}`, `action`, `resource {type, id}` |

**Expected answers**
- A permit is exactly `{"decision": true}`. Anything else is a deny: `false`, a missing or non-boolean
  `decision`, a per-evaluation error.
- An HTTP status other than 200 is an error, not a deny (12.4).
- A batch answer must have one decision per request.
- A search answer has `results`, plus `page.next_token` while more pages remain (`""` when done). Laocoon asks for
  pages of 200 and stops at 20 pages: a larger answer fails closed.

**Properties (Laocoon's profile).** AuthZEN requires search results to carry only `type` and `id`. To resolve
names, label approval cards and offer scope enums, Laocoon reads each result's `properties` (for example
`{"code": "CS101", "title": "…"}`) when present.
- `context.laocoon.reference` is a hint your PDP **may** use to narrow a directory search. If it does, it must
  still return every resource with a property that contains the reference, ignoring case and spaces.
- **Without properties:** references work by id only, there are no scope enums, cards show ids, and filters that
  need labels drop their rows. Every gap fails closed.

**Discovery.** Laocoon reads `/.well-known/authzen-configuration`:
- metadata whose `policy_decision_point` differs from the configured address is **refused**;
- without metadata, Laocoon uses the standard paths and no batch endpoint.

### 12.3 Identity

With system-message identity, Laocoon reads the identity block strictly. Each label must appear exactly once, and
a duplicated `Role:` line rejects the request. It then asks:

```json
{"subject":  {"type": "user", "id": "42", "properties": {"username": "ana", "role": "agent"}},
 "action":   {"name": "identity"},
 "resource": {"type": "user", "id": "42"}}
```

Your PDP must permit this only when user 42 really is `ana` with role `agent`. Anything else answers 401. With the
signed identity header, no identity question is asked.

### 12.4 Security and failure

| Rule | Behaviour |
|---|---|
| Transport | `https://` only, except `localhost`. A custom CA bundle: `LAOCOON_AUTHZEN_CA` |
| Authentication to your PDP | `Authorization: Bearer <LAOCOON_AUTHZEN_TOKEN>` |
| `X-Request-ID` | sent with every request. An answer echoing a different value is rejected; a missing echo is counted |
| The PDP unreachable, an HTTP error, a malformed answer | constraints and references are denied (`abac_unverifiable`, severity medium, nobody is frozen); the identity check fails (401); no scope enums; scope filters drop rows |
| Caching | evaluations: never. Searches: `LAOCOON_AUTHZEN_CACHE_TTL` seconds (default 2) |
| Values | Laocoon never asks for values: approval cards show "—" for before-values. A relation to a non-user object (a submission's assignment) cannot be asked, so that line of a card shows nothing. |

---

## 13. Example

[`eclass.yaml`](eclass.yaml) is the complete policy for Athena eClass: 30 tools, three roles, private data, the
classifier, a `data_model` and an `authzen` mapping. The [guide](README.md) builds a smaller one step by step.
