# Remediation — Secure Code Examples

This document expands on the remediation section of the formal report with full code examples, explanations, and additional hardening guidance.

---

## Fix 1 — Parameterized Queries (Primary — Mandatory)

### Why the current code is vulnerable

The DVWA blind SQLi module builds its SQL query by directly concatenating user-supplied input:

```php
// VULNERABLE — $id comes from $_GET['id'] with no sanitization
$getid = "SELECT first_name, last_name FROM users WHERE user_id = '$id';";
$result = mysqli_query($GLOBALS["___mysqli_ston"], $getid);
```

If a user submits `1' AND SLEEP(5)--`, the query becomes:

```sql
SELECT first_name, last_name FROM users WHERE user_id = '1' AND SLEEP(5)--';
```

The injected SQL is executed by the database engine. The application cannot distinguish between data and code.

---

### The fix — PDO Prepared Statements

```php
<?php
// Establish PDO connection (do this once, e.g. in a config file)
$dsn = 'mysql:host=localhost;dbname=dvwa;charset=utf8mb4';
$options = [
    PDO::ATTR_ERRMODE            => PDO::ERRMODE_EXCEPTION,
    PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC,
    PDO::ATTR_EMULATE_PREPARES   => false,  // critical — use real prepared statements
];
$pdo = new PDO($dsn, 'db_username', 'db_password', $options);

// Validate input type before it reaches the DB layer
$id = $_GET['id'] ?? '';
if (!ctype_digit($id)) {
    // Reject non-numeric input immediately — never let it reach the query
    die('Invalid input.');
}

// Parameterized query — the ? placeholder is never treated as SQL
$stmt = $pdo->prepare("SELECT first_name, last_name FROM users WHERE user_id = ?");
$stmt->execute([(int)$id]);
$result = $stmt->fetchAll();

if ($result) {
    foreach ($result as $row) {
        echo "User ID exists in the database.";
        // render $row['first_name'], $row['last_name'] etc.
    }
} else {
    echo "User ID is MISSING from the database.";
}
?>
```

**Why this works:** The `?` placeholder is sent to the database as a separate parameter — the database engine receives the query structure and the data value independently. Even if the user submits `1' OR '1'='1`, it is treated as a literal string to match against `user_id`, not as SQL syntax. Injection is structurally impossible.

> ⚠️ `PDO::ATTR_EMULATE_PREPARES => false` is critical. Without it, PDO falls back to simulating prepared statements in PHP rather than using real DB-level parameterization — defeating the protection on some MySQL versions.

---

## Fix 2 — Replace MD5 with bcrypt (Secondary — Mandatory)

### Why MD5 is not safe for passwords

MD5 was designed as a fast checksum algorithm, not a password storage function. This makes it dangerous for passwords because:

- **Speed is the enemy** — modern GPUs can compute billions of MD5 hashes per second, making brute force trivial
- **No salt in DVWA** — identical passwords produce identical hashes, enabling rainbow table attacks
- **Widely precomputed** — MD5 hashes of common passwords (like `password` → `5f4dcc3b5aa765d61d8327deb882cf99`) are publicly indexed and instantly reversible

SQLMap cracked all five DVWA accounts in seconds using its built-in dictionary for exactly these reasons.

---

### The fix — bcrypt via PHP `password_hash()`

```php
<?php
// ❌ NEVER do this for passwords
$insecure_hash = md5($password);

// ✅ Hashing a new password at registration
$secure_hash = password_hash($password, PASSWORD_BCRYPT);
// bcrypt automatically generates a unique random salt per hash
// $secure_hash looks like: $2y$10$abcdefghijklmnopqrstuuABCDEFGHIJKLMNOPQRSTUVWXYZ01234

// Store $secure_hash in the database

// ✅ Verifying at login — password_verify handles the salt automatically
$stored_hash = $row['password']; // retrieved from DB
if (password_verify($user_input_password, $stored_hash)) {
    // Passwords match — login success
} else {
    // Passwords do not match — login failure
}

// ✅ Optional: upgrade hash strength over time
if (password_needs_rehash($stored_hash, PASSWORD_BCRYPT)) {
    $new_hash = password_hash($user_input_password, PASSWORD_BCRYPT);
    // Update the stored hash in the database
}
?>
```

**Argon2id (stronger alternative for PHP 7.3+):**

```php
$hash = password_hash($password, PASSWORD_ARGON2ID);
// Argon2id is the current OWASP-recommended choice for new systems
// password_verify() works identically — no other changes needed
```

---

## Fix 3 — Input Validation (Defense-in-Depth)

Never rely on input validation alone — it is a secondary layer, not a replacement for parameterized queries. But it stops obvious attacks early and keeps bad data out entirely.

```php
<?php
function validateUserId($input): int {
    // Accept only positive integers
    $filtered = filter_var($input, FILTER_VALIDATE_INT, [
        'options' => ['min_range' => 1]
    ]);

    if ($filtered === false) {
        http_response_code(400);
        exit('Invalid user ID.');
    }

    return $filtered;
}

$id = validateUserId($_GET['id'] ?? '');
// $id is now guaranteed to be a positive integer before touching the DB
?>
```

---

## Fix 4 — Least-Privilege Database User

The application's database account should have the minimum privileges necessary to function.

```sql
-- Create a restricted application user
CREATE USER 'dvwa_app'@'localhost' IDENTIFIED BY 'strong_random_password';

-- Grant only what the application actually needs
GRANT SELECT, INSERT, UPDATE ON dvwa.* TO 'dvwa_app'@'localhost';

-- Explicitly deny dangerous privileges
REVOKE DROP, CREATE, ALTER, FILE ON *.* FROM 'dvwa_app'@'localhost';

FLUSH PRIVILEGES;
```

With this in place, even a successful SQL injection cannot drop tables, read system files, or write web shells — significantly limiting the blast radius.

---

## Fix 5 — Suppress Verbose Error Messages

Never expose raw database errors to end users. They reveal table names, column names, and query structure — all useful to an attacker.

```php
<?php
// In production — generic error only
try {
    $stmt = $pdo->prepare("...");
    $stmt->execute([$id]);
} catch (PDOException $e) {
    // Log the real error server-side for debugging
    error_log('DB error: ' . $e->getMessage());

    // Show the user nothing useful
    http_response_code(500);
    exit('An error occurred. Please try again later.');
}
?>
```

---

## Fix 6 — Rate Limiting (Anti-Automation)

SQLMap works by sending thousands of rapid requests. Rate limiting does not prevent manual injection but significantly disrupts automated tools.

**Using Apache `.htaccess`:**
```apache
# Limit to 30 requests per 10 seconds per IP on this endpoint
<Location /dvwa/vulnerabilities/sqli_blind/>
    SetEnvIf Request_URI "." LIMIT_THIS
</Location>
```

**Using Nginx:**
```nginx
limit_req_zone $binary_remote_addr zone=sqli_endpoint:10m rate=30r/m;

location /dvwa/vulnerabilities/sqli_blind/ {
    limit_req zone=sqli_endpoint burst=10 nodelay;
}
```

**At the application layer (PHP token bucket example):**
```php
// Check request rate using APCu or Redis before processing
$key = 'rate_limit_' . $_SERVER['REMOTE_ADDR'];
$count = apcu_inc($key, 1, $success, 10); // 10 second TTL
if ($count > 30) {
    http_response_code(429);
    exit('Too many requests.');
}
```

---

## Summary Checklist

| Fix | Priority | Status |
|-----|----------|--------|
| Parameterized queries (PDO) | 🔴 Critical | Replace all dynamic SQL concatenation |
| Replace MD5 with bcrypt/Argon2id | 🔴 Critical | Migrate all stored password hashes |
| Input type validation | 🟠 High | Validate `id` is a positive integer |
| Least-privilege DB user | 🟠 High | Restrict app DB account permissions |
| Suppress verbose DB errors | 🟡 Medium | Use generic error pages in production |
| Rate limiting on endpoint | 🟡 Medium | Implement at server or app layer |

---

## References

- [OWASP SQL Injection Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html)
- [OWASP Password Storage Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html)
- [PHP Manual — PDO Prepared Statements](https://www.php.net/manual/en/pdo.prepared-statements.php)
- [PHP Manual — password_hash()](https://www.php.net/manual/en/function.password-hash.php)
- [NIST SP 800-63B — Digital Identity Guidelines](https://pages.nist.gov/800-63-3/sp800-63b.html)
