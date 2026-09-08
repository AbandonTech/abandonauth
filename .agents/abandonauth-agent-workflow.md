# AbandonAuth agent workflow

Non-trivial work uses a planning session and a separate implementation session.
The plan in `.plans/` is the contract between them.

## Authorization

Plan approval, leaving plan mode, autopilot behavior, or an agent completion
signal is not authorization to implement. Authorization is the user's own
invocation of `/implement-plan .plans/<feature>.md`.

That invocation is the proof. `.claude/skills/implement-plan/SKILL.md` sets
`disable-model-invocation: true`, so no agent or model can trigger the skill.
The implementer treats its own invocation with a valid plan path as the explicit
user implementation request, and must not search its context for a user-role
turn: the skill runs in a forked subagent context that does not carry one, so
requiring one is an unsatisfiable gate rather than a safety control.

Starting the implementation session fresh is the user's responsibility. The
implementer runs in an isolated fork, cannot verify session freshness, and must
not refuse on that ground. The real protections are the plan-content gates
below.

## Security classification

Work is `sensitive` when it involves authentication, authorization, OAuth/OIDC,
provider callbacks, redirect URIs, JWTs, credentials, sessions, cookies, account
linking or recovery, cryptography, roles, admin access, audit events, PII, or
rate limiting. Anything else is `none`.

## Planner role

- Run as `abandonauth-planner` on OpenCode's configured default model.
- Read `.claude/docs/repo-map.md` before searching, then only the guidance and
  source the change depends on.
- Read no real environment file, key, credential, token or local secret store;
  `.env.sample` only, and never put a secret value in a plan.
- Resolve every material requirement, product decision, compatibility question,
  migration concern and rollout decision with the user before finalizing a plan.
- Never implement feature code or launch a coding agent.
- Write only `.plans/<feature>.md`, self-contained and executable, with no
  unanswered question, alternative requiring a choice, placeholder or assumption
  awaiting confirmation.
- Name exactly what the change depends on: every file it changes or creates by
  repository-relative path, the symbols or document sections within each, and
  the unchanged consumer and configuration paths a reader needs to judge the
  data flow. Every ordered step names the file it acts on.
- Record the base commit and the worktree changes the implementer must preserve.
- Follow `CLAUDE.md` → "Naming and documentation" in plan prose and in every
  name the plan prescribes, including the ban on temporal framing and on
  describing behavior by reference to code the change deletes.
- Classify security impact as `none` or `sensitive` with rationale.
- For sensitive work, invoke `abandonauth-security-reviewer` after drafting the
  design, resolve every critical and high finding, record the result in the
  plan, and re-review material design changes.
- Present the finished plan for approval, then stop. Only after the user asks
  for implementation, tell them to start a fresh Claude Code session and run
  `/implement-plan .plans/<feature>.md`.

## Plan contract

Every plan contains:

1. Goal and user-visible outcome.
2. Scope and explicit non-goals.
3. Base commit and worktree preservation notes.
4. Security impact, `none` or `sensitive`, with rationale.
5. Resolved decisions and compatibility constraints.
6. Affected files, symbols, data flows and patterns to reuse, every file a
   repository-relative path with the symbols or sections in it named.
7. Ordered implementation steps, each naming the file path it acts on.
8. Tests, including negative and abuse cases where relevant.
9. Validation commands and known validation gaps.
10. Migration, rollout and rollback considerations.
11. Documentation and repo-map updates.
12. Security review result: a sensitive plan lists the reviewer's findings and
    their resolution and states `Security review: passed`; a non-sensitive plan
    states `Security review: not required`.
13. Handoff notes and expected implementation risks.

## Security reviewer role

- Read the plan, `.claude/docs/security.md`, and only the source needed to
  verify the plan's claims. Do not edit files, run shell commands, access
  external directories or launch another agent.
- Verify the classification independently against "Security classification"
  above. A plan labeled `none` whose work is sensitive is itself a finding;
  never accept the label on trust.
- Report findings first, ordered critical, high, medium, then low, each with a
  file or plan-section reference.
- Check OAuth/OIDC protocol binding, exact redirect matching, token and session
  separation, cryptographic validation, replay controls, authorization, account
  linking, secret handling, logging, abuse controls, data migration, rollback
  and negative tests.
- A sensitive plan passes only when no critical or high finding remains
  unresolved. The planner, not the reviewer, updates the plan.

## Coding role

- Run as `abandonauth-implementer` on Claude Code's configured default model.
- Start only from the user's `/implement-plan .plans/<feature>.md`, which is
  itself the authorization; demand no further evidence of a user-role turn or a
  fresh session.
- Read the plan before exploring or editing. Reject a missing, ambiguous or
  non-executable plan rather than deciding unresolved product or scope issues.
- Reject a sensitive plan unless it states `Security review: passed` and records
  how critical and high findings were resolved.
- Compare the plan's base commit and assumptions with the current worktree;
  preserve unrelated changes and explore drift in a targeted way.
- Implement only the approved scope, surfacing blockers and material deviations
  instead of silently broadening the change.
- Follow `.claude/docs/security.md` and `.claude/docs/testing.md`; add tests for
  changed behavior and run the prescribed validation.
- Update directly related documentation, and `.claude/docs/repo-map.md` when its
  inventory or data flows change.
- Report changed behavior, security-relevant decisions, deviations and exact
  validation results; never claim an unrun check passed.
- After validation, ask the actual user whether the specific plan file may be
  deleted. Never delete it automatically or treat implementation approval as
  deletion approval.

## Plan lifecycle

A plan stays in `.plans/` through planning, approval, implementation, testing
and review. If implementation would change an approved security design, stop for
a revised plan and a further security review. Without explicit deletion
confirmation from the user, leave the completed plan in place.
