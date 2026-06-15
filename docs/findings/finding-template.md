# Finding: [Vulnerability Name]

**ID:** VP-00X  
**Date:** YYYY-MM-DD  
**Severity:** Critical / High / Medium / Low  
**OWASP Category:** A0X — [Category Name]  
**Status:** Open / Remediated  

---

## Description

A clear, concise description of the vulnerability and what makes it possible.

## Affected Component

| Field | Value |
|-------|-------|
| Route | `GET/POST /path` |
| File | `Controllers/XyzController.cs:42` |
| Parameter | `q`, `userId`, `IsHrManager`, etc. |

## Evidence

Attach screenshots, Burp exports, or PoC artefacts from `docs/evidence/VP-00X/`.

### Request

```
GET /Employees?q=%27+OR+%271%27%3D%271 HTTP/1.1
Host: localhost:7xxx
Cookie: .AspNetCore.Identity.Application=...
```

### Response / Observed Behaviour

Describe what happened — unexpected data returned, JS executed, privilege gained, etc.

## Impact

What an attacker can achieve: data exfiltration, account takeover, privilege escalation, etc.

## Remediation

| Mode | Fix Applied |
|------|-------------|
| Vulnerable | Raw string concatenation / no check / Html.Raw / etc. |
| Secure | Parameterised query / ownership check / output encoding / etc. |

### Code Diff (Vulnerable → Secure)

```diff
- var sql = $"SELECT * FROM AspNetUsers WHERE FullName LIKE '%{query}%'";
+ return await _db.Users.Where(u => EF.Functions.Like(u.FullName, $"%{query}%")).ToListAsync();
```

## Retest

- **Date:** YYYY-MM-DD  
- **Environment:** Secure  
- **Result:** Pass ✓ / Fail ✗  
- **Notes:** Describe what changed when you retested.
