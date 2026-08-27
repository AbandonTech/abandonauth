---
name: implement-plan
description: Implements an approved AbandonAuth plan in a fresh Claude Code context. Use only when the user explicitly requests implementation and provides a .plans path.
disable-model-invocation: true
context: fork
agent: abandonauth-implementer
background: false
argument-hint: <.plans/file.md>
---

If `$ARGUMENTS` is missing, is outside `.plans/`, does not name a Markdown
file, or names a file that does not exist, stop and ask the user for a valid
approved plan path. Do not explore or edit first.

Read the validated plan before exploring or editing. Implement it only when the
user explicitly requested implementation in this newly started Claude Code
session, then follow the Coding role in
`.agents/abandonauth-agent-workflow.md`.

If the plan has unanswered questions, alternatives requiring a decision,
placeholders, or assumptions awaiting confirmation, stop and send it back to
the planner. If it is security-sensitive, require `Security review: passed`
and recorded resolution of every critical and high finding. Do not implement
or decide missing product, scope, or security-design details.
