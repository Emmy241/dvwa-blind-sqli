# Suggested Git Commit History

Push your commits in this order to tell a clean story through your git log.

---

```bash
# 1 — repo scaffolding
git commit -m "Initial commit — project structure and disclaimer"

# 2 — recon phase
git commit -m "Recon: attempted classic SQLi on login form — unsuccessful"

# 3 — blind sqli confirmation
git commit -m "Discovery: confirmed boolean-based blind SQLi on id parameter (ID=1)"

# 4 — sqlmap db enumeration
git commit -m "Exploitation: SQLMap --dbs enumerated dvwa and information_schema"

# 5 — table and column dump
git commit -m "Exploitation: dumped users table — user_id and password columns identified"

# 6 — credential recovery
git commit -m "Exploitation: full credential dump — all 5 MD5 hashes cracked to plaintext"

# 7 — report
git commit -m "Report: added formal vulnerability assessment document"

# 8 — remediation
git commit -m "Remediation: parameterized queries, bcrypt migration, and additional controls"

# 9 — final polish
git commit -m "Docs: finalized README, payload notes, and evidence placeholders"
```

---

This sequence makes your git history read like a professional pentest workflow —
recon → discovery → exploitation → reporting → remediation.
