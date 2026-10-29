---
name: implement-plan
description: Implements an approved AbandonAuth plan in an isolated implementation context. Invoked only by the user, with a .plans path.
disable-model-invocation: true
context: fork
agent: abandonauth-implementer
background: false
argument-hint: <.plans/file.md>
---

If `$ARGUMENTS` is missing, is outside `.plans/`, does not name a Markdown
file, or names a file that does not exist, stop and ask the user for a valid
approved plan path. Do not explore or edit first.

Read the validated plan before exploring or editing. This skill cannot be
invoked by a model, so its invocation is the user's explicit implementation
request: implement the plan, following
`.agents/abandonauth-agent-workflow.md` → "Coding role". Do not require further
proof of user intent or session freshness.

If the plan has unanswered questions, alternatives requiring a decision,
placeholders, or assumptions awaiting confirmation, stop and send it back to the
planner. A security-sensitive plan additionally requires `Security review:
passed` and recorded resolution of every critical and high finding. Do not
implement or decide missing product, scope, or security-design details.
