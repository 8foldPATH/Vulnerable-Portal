# Dodgy Portal — Deliberately Vulnerable ASP.NET Core Employee Portal

A deliberately vulnerable internal employee portal built for structured security assessment practice. It mirrors a realistic business intranet application and pairs each intentional flaw with an OWASP-aligned remediation, so you can demonstrate discovery, documentation, and fix validation as a portfolio piece.

> **For authorised training and assessment only. Do not deploy publicly without hardening.**

---

## Tech Stack

| Layer | Technology |
|-------|-----------|
| Language | C# 12 |
| Framework | ASP.NET Core 8 MVC |
| ORM | Entity Framework Core 8 |
| Database | SQLite |
| Auth | ASP.NET Core Identity |
| UI | Bootstrap 5 + Bootstrap Icons |

---

## Quick Start

**Prerequisites:** [.NET 8 SDK](https://dotnet.microsoft.com/download/dotnet/8.0)

```bash
# Clone and run in Vulnerable mode — no other setup needed
git clone <repo-url>
cd Vulnerable-Portal
dotnet run --project src/Portal.Web --launch-profile Vulnerable
```

The app creates the SQLite database, runs all schema migrations, and seeds demo accounts automatically on first launch. The URL is printed in the terminal output (typically `http://localhost:5XXX`).

---

## Running in Secure Mode

Toggle the `ASPNETCORE_ENVIRONMENT` variable to switch between the two profiles:

```bash
# Vulnerable (default) — all 9 flaws active
dotnet run --project src/Portal.Web --launch-profile Vulnerable

# Secure — all flaws remediated
dotnet run --project src/Portal.Web --launch-profile Secure
```

A colour-coded banner at the top of every page confirms the active profile:

- **Red banner** — Vulnerable mode, flaws exploitable
- **Green banner** — Secure mode, controls enforced

The home dashboard lists all active vulnerabilities and links to each affected feature.

---

## Demo Accounts

| Email | Password | Role |
|-------|----------|------|
| admin@acme.com | Admin123! | Admin |
| employee1@acme.com | Employee123! | Employee |
| employee2@acme.com | Employee123! | Employee |

---

## Vulnerability Map

| # | Name | Route | Flaw (Vulnerable) | Remediation (Secure) | OWASP |
|---|------|-------|-------------------|----------------------|-------|
| 1 | SQL Injection | `GET /Employees?q=` | String concatenation into raw SQL | EF Core parameterised `LIKE` | A03 |
| 2 | Stored XSS | `GET /Announcements/Details/{id}` | `Html.Raw()` renders stored content | Razor default HTML encoding | A03 |
| 3 | Broken Access Control — Admin | `GET /Admin` | No `[Authorize]` attribute | `[Authorize(Roles="Admin")]` check | A01 |
| 4 | IDOR — Expense Reports | `GET /Expenses/Details/{id}` | No ownership check on report ID | Compares `EmployeeId` to current user | A01 |
| 5 | No Account Lockout | `POST /Account/Login` | `lockoutOnFailure: false` | `lockoutOnFailure: true`, 5-attempt limit | A07 |
| 6 | Mass Assignment | `POST /Profile/Edit` | `IsHrManager` read from raw form data | DTO excludes privileged field | A08 |
| 7 | Insecure File Upload | `POST /Expenses/Upload/{id}` | All types accepted, original filename, public URL | Extension whitelist, GUID filename, auth download | A01 |
| 8 | Weak Remember-Me | `POST /Account/Login` | `RememberToken=Base64(email)`, `HttpOnly=false` | Identity persistent cookie, `HttpOnly=true` | A07 |
| 9 | Sensitive Data via URL | `GET /Profile?userId=` | Any user's profile returned, IDs logged | Always returns own profile, no ID logging | A02/A09 |

---

## Repository Layout

```
Dodgy-Portal/
├── docs/
│   ├── assessment/
│   │   ├── methodology.md       # Scope, workflow, tool recommendations
│   │   └── testing-guide.md     # Step-by-step exploit instructions for all 9 vulns
│   ├── findings/
│   │   └── finding-template.md  # Per-finding report template
│   └── evidence/                # Burp exports, screenshots, PoC artefacts
├── src/
│   └── Portal.Web/
│       ├── Configuration/
│       │   └── SecurityProfile.cs   # Reads ASPNETCORE_ENVIRONMENT, drives all mode switches
│       ├── Controllers/             # One controller per feature area
│       ├── Data/
│       │   ├── ApplicationDbContext.cs
│       │   └── SeedData.cs          # Creates roles, users, announcements, expenses on startup
│       ├── Models/
│       │   ├── ApplicationUser.cs   # Extends IdentityUser with FullName, Department, IsHrManager
│       │   ├── Announcement.cs
│       │   ├── ExpenseReport.cs
│       │   ├── FileAttachment.cs
│       │   └── ViewModels/          # DTOs used by controllers — ProfileEditViewModel is the mass-assignment fix
│       ├── Services/
│       │   ├── IEmployeeSearchService.cs
│       │   ├── VulnerableEmployeeSearchService.cs   # SQLi implementation
│       │   ├── SecureEmployeeSearchService.cs       # Parameterised implementation
│       │   ├── IFileUploadService.cs
│       │   ├── VulnerableFileUploadService.cs       # Accepts anything, original filename
│       │   └── SecureFileUploadService.cs           # Extension whitelist, GUID filename
│       ├── Views/                   # Razor views — XSS flaw lives in Announcements/Details.cshtml
│       ├── wwwroot/uploads/         # File upload target (public in vulnerable mode)
│       └── Program.cs              # DI wiring: registers Vulnerable or Secure services by environment
├── DodgyPortal.sln
└── README.md
```

---

## How the Dual-Mode Works

`Program.cs` reads `ASPNETCORE_ENVIRONMENT` at startup and registers either the vulnerable or secure service implementations into the DI container:

```csharp
if (isSecure)
{
    services.AddScoped<IEmployeeSearchService, SecureEmployeeSearchService>();
    services.AddScoped<IFileUploadService, SecureFileUploadService>();
}
else
{
    services.AddScoped<IEmployeeSearchService, VulnerableEmployeeSearchService>();
    services.AddScoped<IFileUploadService, VulnerableFileUploadService>();
}
```

A `SecurityProfile` singleton is also injected everywhere a controller or view needs to conditionally enable/disable a flaw (e.g. IDOR check, lockout flag, `Html.Raw` rendering).

---

## Assessment Workflow

1. Read `docs/assessment/methodology.md` and define your scope.
2. Run the app in **Vulnerable** mode; map all routes with Burp Suite or browser DevTools.
3. Work through each vulnerability using `docs/assessment/testing-guide.md`.
4. Document each finding in `docs/findings/` using the template.
5. Capture screenshots and Burp exports in `docs/evidence/`.
6. Switch to **Secure** mode and retest each finding — expected result is 403/redirect/no output.
7. Record retest outcomes in each finding file.
8. Write an executive summary at `docs/assessment/executive-summary.md` for a hiring manager audience.

---

## Database

No `dotnet ef` commands are needed. The app calls `EnsureCreated()` and seeds data on every startup. If you reset the database, just delete `portal.db` and restart.

```bash
# Reset to a clean state
rm src/Portal.Web/portal.db
dotnet run --project src/Portal.Web
```

---

## Disclaimer

This project contains **real, working exploits**. It is intended solely for:

- Personal portfolio demonstration
- Authorised security training in a local or isolated environment
- Learning OWASP vulnerability classes and their remediations

Do not deploy this application on a public network or any shared infrastructure without first switching to Secure mode and conducting a full security review.
