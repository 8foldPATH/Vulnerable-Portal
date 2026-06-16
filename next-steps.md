# Next Steps — Portfolio Build Plan

A reference for completing the full pen testing → detection engineering → remediation cycle across this project.

---

## The Three Phases

```
Phase 1 — Pen Testing        Phase 2 — Detection          Phase 3 — Remediation
──────────────────────        ────────────────────          ─────────────────────
Attack the portal with        Write Sentinel KQL rules      Switch to Secure mode,
Burp Suite. Document          that fire when those          retest, show the alerts
findings with evidence.       attack patterns are seen.     go silent.
```

The portal already supports Phase 1 and Phase 3. Phase 2 requires bridging the portal into Azure.

---

## Phase 1 — Pen Testing with Burp Suite

Run the portal in Vulnerable mode and work through all 9 vulnerabilities. Don't touch the code during this phase — treat it as a black-box assessment.

```bash
dotnet run --project src/Portal.Web --launch-profile Vulnerable
```

**Burp Suite workflow:**
1. Set Burp as your browser proxy (127.0.0.1:8080).
2. Browse the app logged in as `employee1@acme.com` — let Burp build the site map.
3. Use **Repeater** to manually craft and replay modified requests.
4. Use **Intruder** for the brute force / account lockout test (Vulnerability #5).
5. Export each relevant request/response as evidence (right-click → Save item).

**For each vulnerability:**
- Confirm the exploit works and note exactly what you did
- Screenshot the result (unexpected data, JS alert, privilege change, etc.)
- Save the Burp export to `docs/evidence/VP-00X/`
- Fill in `docs/findings/` using the template

Full step-by-step exploit instructions are in `docs/assessment/testing-guide.md`.

---

## Phase 2 — Detection Engineering (the gap to bridge)

### Why a data source is needed

Sentinel doesn't passively watch the machine — it only knows what logs are fed into a **Log Analytics workspace**. The portal is currently invisible to it. The bridge is **Application Insights**.

### Recommended architecture

```
Your Mac
├── Portal running locally (http://localhost:5121)
├── Burp Suite — intercept, replay, and attack traffic
└── Browser → Portal → Burp proxy

Azure (free tier / pay-as-you-go, very low cost for local volumes)
├── Log Analytics Workspace  ← the data store Sentinel queries
├── Microsoft Sentinel       ← analytics rules, alerts, incidents
└── Application Insights     ← SDK in the portal ships telemetry here
```

### Step 2a — Add Application Insights to the portal

One NuGet package and ~5 lines in `Program.cs`. Application Insights automatically captures:
- Every HTTP request (URL, query string, status code, duration, user identity)
- Exceptions
- Custom events emitted from code
- Dependency calls (EF Core database queries)

This is the lowest-effort path to getting web application layer telemetry into Sentinel — network-only approaches miss query strings and POST bodies, which is where the attack payloads live.

### Step 2b — Create the Azure resources

All of the following can be done in the Azure Portal in under 10 minutes:
1. Create a **Log Analytics workspace** (free 5 GB/month ingestion)
2. Enable **Microsoft Sentinel** on that workspace
3. Create an **Application Insights** resource pointing at the same workspace

### Step 2c — Re-run attacks with telemetry flowing

Repeat each Burp Suite attack from Phase 1. This time the HTTP requests, exceptions, and log lines are shipped to Azure and available in KQL.

---

## Detection Rules to Write (one per vulnerability)

Once telemetry is flowing, these KQL analytics rules are all achievable in Sentinel. Write them under **Sentinel → Analytics → Create → Scheduled query rule**.

| # | Vulnerability | Table | Detection logic |
|---|--------------|-------|-----------------|
| 1 | SQL Injection | `requests` | `url` or `url_query` contains `' OR`, `UNION SELECT`, `1=1`, or `--` |
| 2 | Stored XSS | `requests` | POST to `/Announcements/Create` where request body contains `<script` |
| 3 | Admin bypass | `requests` | `GET /Admin` where `resultCode == 200` and no authenticated session claim |
| 4 | IDOR enumeration | `requests` | Same `session_Id` hits `/Expenses/Details/` 3+ different IDs within 60 seconds |
| 5 | Brute force | `requests` | 5+ `POST /Account/Login` returning HTTP 200 (failed auth) from same IP in 60 seconds |
| 6 | Mass assignment | `requests` | POST to `/Profile/Edit` where request body contains `IsHrManager=true` |
| 7 | Insecure upload | `requests` | POST to `/Expenses/Upload` where uploaded filename ends in `.html`, `.php`, `.exe` |
| 8 | Weak remember-me | `requests` | Presence of `RememberToken` cookie on requests (detects the vulnerable cookie being set) |
| 9 | Sensitive URL / log leakage | `traces` | Log message contains `"Profile viewed: userId="` — the portal already emits this via `ILogger` |

The **brute force** rule is the easiest to start with (simple count-over-time query).  
The **log leakage** rule (Vulnerability #9) is particularly neat — the portal already emits the log line, Application Insights captures it as a `trace`, and the KQL rule is a single `where` filter.

---

## Phase 3 — Remediation Validation

Switch to Secure mode:

```bash
dotnet run --project src/Portal.Web --launch-profile Secure
```

For each vulnerability:
1. Repeat the same Burp attack from Phase 1.
2. Confirm the attack fails (403, redirect, no unexpected data).
3. Check the Sentinel analytics rule — the alert should either not fire, or fire differently (e.g. the brute force rule still fires but the lockout response shows in the log).
4. Record the retest result in the finding file.

---

## The Complete Portfolio Piece (per vulnerability)

| Artefact | Where it lives |
|----------|---------------|
| Finding report | `docs/findings/VP-00X-<name>.md` |
| Burp export / screenshot | `docs/evidence/VP-00X/` |
| KQL detection rule | `docs/detections/VP-00X-<name>.kql` (create this folder) |
| Alert screenshot from Sentinel | `docs/evidence/VP-00X/sentinel-alert.png` |
| Retest result | Bottom of the finding report |
| Executive summary | `docs/assessment/executive-summary.md` |

A complete finding with all six artefacts demonstrates the full offensive + defensive cycle in a single document trail — which is unusual for a portfolio and is the main differentiator.

---

## Suggested Order of Work

- [ ] **1. Pen test** — work through all 9 vulnerabilities with Burp Suite, capture evidence, fill in finding templates
- [ ] **2. Add Application Insights** — NuGet package + config in `Program.cs` (ask Claude to do this)
- [ ] **3. Create Azure resources** — Log Analytics workspace + Sentinel + Application Insights in Azure Portal
- [ ] **4. Re-run attacks with telemetry flowing** — repeat Burp attacks, confirm data appears in Log Analytics
- [ ] **5. Write KQL rules** — start with brute force, then SQLi, then IDOR enumeration
- [ ] **6. Capture Sentinel alert screenshots** — evidence of the detection working
- [ ] **7. Add `docs/detections/` folder** — one `.kql` file per rule with explanation comments
- [ ] **8. Retest in Secure mode** — confirm attacks fail and alerts go quiet
- [ ] **9. Write executive summary** — one page, non-technical, for a hiring manager audience

---

## Notes on the Environment

- **Burp Suite** — use the Community Edition Intruder (slower but functional) for brute force; Repeater for manual IDOR and mass assignment
- **Sentinel** — the free 90-day trial includes the Sentinel add-on; after that it's ~$2/GB ingested (negligible for local volumes)
- **Microsoft Defender** — if you run the portal on a Windows VM with MDE installed, you get lower-level telemetry (process creation, file writes, network connections) on top of the application logs — useful for detecting tools like sqlmap by User-Agent or process name
- **macOS + Defender for Endpoint** — captures endpoint events but not web-layer HTTP traffic; Application Insights is the right tool for that layer
