---
description: Read-only security audit of this git repo - secrets in files and history, exposed commit emails, sensitive tracked files
allowed-tools: Bash(python:*)
---

## sekyu audit report

!`python "${CLAUDE_PLUGIN_ROOT}/hooks/audit.py"`

Summarize the report above for the user, most severe first. For each HIGH item, say what is exposed and the fix (rotate the secret, `git rm --cached`, history rewrite). Group obvious false positives (rule definitions, test fixtures) in one line instead of listing them.

The audit changed nothing. Do not edit files, rewrite history, or change git config unless the user asks.
