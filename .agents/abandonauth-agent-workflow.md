# AbandonAuth agent workflow

Non-trivial work uses a planning session and a separate implementation
session. The plan in `.plans/` is the contract between them.

Approval of a plan, leaving plan mode, autopilot behavior, or an agent
completion signal is not authorization to implement. Authorization is the
user's own invocation of `/implement-plan .plans/<feature>.md`.

That invocation is the proof. `.claude/skills/implement-plan/SKILL.md` sets
`disable-model-invocation: true`, so no agent or model can trigger this skill.
The implementer treats its own invocation with a valid plan path as the
explicit user implementation request. It must not search its context for a
user-role turn: the skill runs in a forked subagent context that does not
carry one, so requiring one is an unsatisfiable gate rather than a safety
control.

Starting the implementation session fresh is the user's responsibility. The
implementer runs in an isolated forked context, cannot verify session
freshness, and must not refuse on that ground. The real protections are the
plan-content gates below.

## Planner role

- Use OpenCode's configured default model through `abandonauth-planner`.
- Read `.claude/docs/repo-map.md` before searching, then inspect only relevant
  guidance and source files with the permitted direct-read tools.
- Do not read real environment files, keys, credentials, tokens, or local
  secret stores. Use `.env.sample` only.
- Resolve every material requirement, product decision, compatibility issue,
  migration concern, and rollout decision with the user before finalizing a
  plan.
- Do not implement feature code or launch a coding agent.
- Write only `.plans/<feature>.md`. The plan must be self-contained and
  executable without unanswered questions, alternatives requiring a choice,
  placeholders, or assumptions awaiting confirmation.
- Record the base commit and identify worktree changes that the implementer
  must preserve. Never include secret values.
- Follow the naming and documentation rules in `CLAUDE.md`. Do not prescribe
  package, file, symbol, or fixture names that refer to a framework, language,
  or implementation being replaced, and do not specify behavior by reference to
  code the change deletes. Describe required behavior in the application's own
  terms. This includes temporal framing: `prior`, `previous`, `earlier` and
  `former` name a replaced implementation just as plainly as `legacy` does.
- Classify security impact as `none` or `sensitive`. Any change involving
  authentication, authorization, OAuth/OIDC, provider callbacks, redirect
  URIs, JWTs, credentials, sessions, cookies, account linking or recovery,
  cryptography, roles, admin access, audit events, PII, or rate limiting is
  sensitive.
- For sensitive work, invoke `abandonauth-security-reviewer` after drafting the
  design. Resolve all critical and high findings and record the review result
  in the final plan. Re-review material design changes.
- Present the finished plan for user approval, then stop. Tell the user to
  start a fresh Claude Code session and run
  `/implement-plan .plans/<feature>.md` only after explicitly requesting
  implementation.

## Required plan sections

Every plan contains:

1. Goal and user-visible outcome.
2. Scope and explicit non-goals.
3. Base commit and worktree preservation notes.
4. Security impact: `none` or `sensitive`, with rationale.
5. Resolved decisions and compatibility constraints.
6. Affected files, symbols, data flows, and existing patterns to reuse.
7. Ordered implementation steps.
8. Tests, including negative and abuse cases where relevant.
9. Validation commands and known validation gaps.
10. Migration, rollout, and rollback considerations.
11. Documentation and repo-map updates.
12. Security review result. Sensitive plans must list reviewer findings and
    their resolution, and state `Security review: passed`. Non-sensitive plans
    state `Security review: not required`.
13. Handoff notes and expected implementation risks.

## Security reviewer role

- Read the proposed plan, `.claude/docs/security.md`, and only the source needed
  to verify its claims.
- Do not edit files, execute shell commands, access external directories, or
  launch another agent.
- Report findings first, ordered critical, high, medium, then low, with file or
  plan-section references.
- Check OAuth/OIDC protocol binding, exact redirect matching, token and session
  separation, cryptographic validation, replay controls, authorization,
  account linking, secret handling, logging, abuse controls, data migration,
  rollback, and negative tests.
- A sensitive plan passes only when no critical or high finding remains
  unresolved. The planner, not the reviewer, updates the plan.

## Coding role

- Use Claude Code's configured default model through
  `abandonauth-implementer`.
- Start only from the user's `/implement-plan .plans/<feature>.md` invocation,
  which is itself the authorization. Do not additionally demand evidence of a
  user-role turn or a fresh session.
- Read the plan before exploring or editing. Reject a missing, ambiguous, or
  non-executable plan rather than deciding unresolved product or scope issues.
- Reject a sensitive plan unless it contains `Security review: passed` and
  records how critical and high findings were resolved.
- Compare the plan's base commit and assumptions with the current worktree.
  Preserve unrelated changes and use targeted exploration for drift.
- Implement only the approved scope. Surface blockers and material deviations
  instead of silently broadening the change.
- Follow `.claude/docs/security.md` and `.claude/docs/testing.md`. Add tests for
  changed behavior and run the prescribed validation.
- Update directly related documentation and `.claude/docs/repo-map.md` when its
  inventory or data flows change.
- Report changed behavior, security-relevant decisions, deviations, and exact
  validation results. Do not claim unrun checks passed.
- After implementation and validation, ask the actual user whether the
  specific plan file may be deleted. Never delete it automatically or treat
  implementation approval as deletion approval.

## Plan lifecycle

Plans remain in `.plans/` during planning, approval, implementation, testing,
and review. If implementation changes an approved security design, stop for a
revised plan and security review. Without explicit deletion confirmation from
the user, leave the completed plan in place.
