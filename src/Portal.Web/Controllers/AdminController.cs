// ============================================================
// AdminController.cs — VULNERABILITY #3: Broken Access Control (Admin Panel)
// ============================================================
// OWASP A01 — Broken Access Control
//
// The flaw: there is no [Authorize] attribute on this controller or its
// action. ASP.NET Core's authorization middleware only enforces access
// control when [Authorize] is applied — without it, every request reaches
// the action regardless of whether the caller is authenticated.
//
// In Vulnerable mode the Index() action performs no checks at all and
// returns the full admin dashboard to any HTTP request. An attacker who
// knows (or guesses) the URL /Admin gets complete visibility into all
// user accounts and pending expense reports without any credentials.
//
// In Secure mode an explicit check is added inside the action:
//   - Unauthenticated users are redirected to the login page
//   - Authenticated non-admin users receive 403 Forbidden
//
// The secure pattern would normally be [Authorize(Roles = "Admin")]
// as a class-level attribute. The in-action approach is used here
// so both behaviours live in the same controller for easy comparison.
// ============================================================

using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using Portal.Web.Configuration;
using Portal.Web.Data;
using Portal.Web.Models;

namespace Portal.Web.Controllers;

// NOTE: No [Authorize] attribute here — that is the vulnerability.
// In a real application every admin controller should have [Authorize(Roles = "Admin")].
public class AdminController : Controller
{
    private readonly ApplicationDbContext _db;
    private readonly UserManager<ApplicationUser> _userManager;
    private readonly SecurityProfile _profile;

    public AdminController(ApplicationDbContext db, UserManager<ApplicationUser> userManager, SecurityProfile profile)
    {
        _db = db;
        _userManager = userManager;
        _profile = profile;
    }

    // GET /Admin — returns the admin dashboard
    public async Task<IActionResult> Index()
    {
        // -------------------------------------------------------
        // VULNERABILITY #3 — No authentication / authorisation check
        // -------------------------------------------------------
        // In Vulnerable mode this block is skipped entirely and the
        // dashboard is served to anyone, even unauthenticated requests.
        //
        // In Secure mode we manually replicate what [Authorize(Roles="Admin")]
        // would do automatically if it were applied as an attribute.
        if (_profile.IsSecure)
        {
            // Step 1: ensure the user is logged in at all
            if (!User.Identity!.IsAuthenticated)
                return RedirectToAction("Login", "Account", new { returnUrl = "/Admin" });

            // Step 2: ensure the logged-in user has the Admin role
            if (!User.IsInRole("Admin"))
                return Forbid(); // returns 403 Forbidden
        }

        // Populate the view with all users and all pending expense reports.
        // This data is sensitive — in a real app it should only be accessible
        // to administrators. In Vulnerable mode anyone can see it.
        ViewBag.Users = await _userManager.Users.ToListAsync();
        ViewBag.PendingExpenses = await _db.ExpenseReports
            .Include(e => e.Employee)
            .Where(e => e.Status == "Pending")
            .OrderByDescending(e => e.CreatedAt)
            .ToListAsync();

        return View();
    }
}
