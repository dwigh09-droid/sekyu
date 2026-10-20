---
name: secure-coding
description: Use when writing or changing code that handles user input, auth, sessions, SQL, file paths, shell commands, HTML output, crypto, or secrets.
---

# Secure coding

Apply these while writing, not after. sekyu scans every edit and reports what slips through.

- **Validate at trust boundaries.** Check type, length, format, and range of every external input (HTTP, CLI args, files, env, third-party APIs). Reject; don't "clean up".
- **Parameterized queries only.** Never build SQL, NoSQL, LDAP, or XPath from string concatenation or f-strings.
- **Encode output for its context.** HTML-escape for HTML, URL-encode for URLs. Prefer `textContent` over `innerHTML`.
- **No shell from input.** Pass argument lists (`subprocess.run([...])`, `execFile`), never `shell=True`, `os.system`, or `eval`/`exec`.
- **Confine file paths.** Resolve the path, then confirm it stays inside the allowed root. Reject `..` escapes and symlinks out.
- **Secrets from env or a secret store.** Never in code, config committed to git, logs, error messages, or URLs.
- **Vetted crypto only.** Passwords: argon2id or bcrypt. Tokens: `secrets` / `crypto.randomBytes`. Never MD5/SHA1 for security, never roll your own.
- **Least privilege.** Narrow-scope tokens, DB users without DDL rights, file permissions no wider than needed.
- **Fail closed.** On auth or permission errors, deny. Check authorization on every request, server side.
- **Safe deserialization.** `json`, `yaml.safe_load`; never `pickle` or unsafe loaders on untrusted data.
- **Keep TLS verification on.** No `verify=False` or `rejectUnauthorized: false`.
- **Don't log tokens, passwords, or PII.**

When sekyu reports a finding: fix the root cause. Use `sekyu: ignore` only on a line you have confirmed safe, with the reason in the same comment.
