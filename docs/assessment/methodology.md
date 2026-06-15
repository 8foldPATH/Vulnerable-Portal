# Assessment Methodology

## Scope

| Asset | In scope |
|-------|----------|
| Portal.Web application (localhost) | Yes |
| SQLite database (portal.db) | Yes |
| wwwroot/uploads directory | Yes |
| Third-party CDN assets (Bootstrap, jQuery) | No |

## Vulnerability Target List

| # | Name | Route | Category | OWASP |
|---|------|-------|----------|-------|
| 1 | SQL Injection | `GET /Employees?q=` | Injection | A03 |
| 2 | Stored XSS | `GET /Announcements/Details/{id}` | Injection | A03 |
| 3 | Broken Access Control — Admin | `GET /Admin` | BAC | A01 |
| 4 | IDOR — Expense Reports | `GET /Expenses/Details/{id}` | BAC | A01 |
| 5 | No Account Lockout | `POST /Account/Login` | Auth | A07 |
| 6 | Mass Assignment | `POST /Profile/Edit` | Integrity | A08 |
| 7 | Insecure File Upload | `POST /Expenses/Upload/{id}` | BAC | A01 |
| 8 | Weak Remember-Me Token | `POST /Account/Login` (RememberMe) | Auth | A07 |
| 9 | Sensitive Data via URL | `GET /Profile?userId=` | Exposure | A02/A09 |

## Workflow

1. Start the app in **Vulnerable** mode (default):
   ```
   dotnet run --project src/Portal.Web
   ```
2. Log in with a demo account. Map all routes with Burp Suite or browser DevTools.
3. Attempt each vulnerability using the techniques in `testing-guide.md`.
4. Document each finding using `docs/findings/finding-template.md`.
5. Capture evidence under `docs/evidence/`.
6. Switch to **Secure** mode and retest:
   ```
   ASPNETCORE_ENVIRONMENT=Secure dotnet run --project src/Portal.Web
   ```
7. Record retest results (expected: all findings remediated) in each finding file.
8. Write an executive summary at `docs/assessment/executive-summary.md`.

## Tools Recommended

- **Burp Suite Community/Pro** — intercepting proxy, Intruder for brute force
- **curl** — scripting auth flows and POST manipulation
- **Browser DevTools** — editing requests (Network → Edit and Resend), reading cookies
- **sqlmap** (optional) — automated SQLi confirmation
