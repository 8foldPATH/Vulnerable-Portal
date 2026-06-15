// ============================================================
// AnnouncementsController.cs — XSS injection sink (Vulnerability #2)
// ============================================================
// OWASP A03 — Injection (Stored XSS)
//
// The vulnerability is NOT in this controller — it's in the Razor view
// (Views/Announcements/Details.cshtml). The controller stores announcement
// content in the database exactly as submitted; that's fine. The problem
// is that the view renders the stored content with @Html.Raw() in Vulnerable
// mode, which bypasses ASP.NET Core's automatic HTML encoding.
//
// Why the flaw is "stored" XSS:
//   Reflected XSS: the payload arrives in the current HTTP request and is
//     immediately echoed back in the response. It only affects the attacker.
//   Stored XSS: the payload is saved to the database. Every user who views
//     the affected page executes the script. One injection → many victims.
//
// The controller's Create action is the injection point — it accepts the
// content from the form and writes it to the database without sanitisation.
// Sanitising at storage time is a common but incomplete approach (encoding
// may break legitimate content); the correct fix is to sanitise at render
// time, which Razor does by default unless overridden with Html.Raw().
// ============================================================

using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using Portal.Web.Data;
using Portal.Web.Models;
using Portal.Web.Models.ViewModels;

namespace Portal.Web.Controllers;

[Authorize]
public class AnnouncementsController : Controller
{
    private readonly ApplicationDbContext _db;
    private readonly UserManager<ApplicationUser> _userManager;

    public AnnouncementsController(ApplicationDbContext db, UserManager<ApplicationUser> userManager)
    {
        _db = db;
        _userManager = userManager;
    }

    // GET /Announcements — list all announcements, newest first
    public async Task<IActionResult> Index()
    {
        var announcements = await _db.Announcements
            .Include(a => a.Author)   // Load the Author navigation property for display
            .OrderByDescending(a => a.CreatedAt)
            .ToListAsync();
        return View(announcements);
    }

    // GET /Announcements/Details/{id} — VIEW WHERE XSS EXECUTES
    // The controller just fetches the record and passes it to the view.
    // Whether the content is encoded or raw depends on the view, not here.
    // See Views/Announcements/Details.cshtml for the Html.Raw() call.
    public async Task<IActionResult> Details(int id)
    {
        var announcement = await _db.Announcements
            .Include(a => a.Author)
            .FirstOrDefaultAsync(a => a.Id == id);

        if (announcement == null) return NotFound();
        return View(announcement);
    }

    // GET /Announcements/Create — show the form for a new announcement
    // This is the XSS INJECTION POINT — users submit payloads here.
    // The form accepts any content, which is stored verbatim.
    [HttpGet]
    public IActionResult Create() => View();

    // POST /Announcements/Create — save the announcement
    // Content is saved exactly as submitted — no sanitisation here.
    // Sanitising at this stage would be input filtering, which is fragile.
    // The correct control is output encoding at render time (see the view).
    [HttpPost, ValidateAntiForgeryToken]
    public async Task<IActionResult> Create(AnnouncementCreateViewModel model)
    {
        if (!ModelState.IsValid) return View(model);

        var user = await _userManager.GetUserAsync(User);
        var announcement = new Announcement
        {
            Title = model.Title,
            Content = model.Content,   // Stored verbatim — payload survives here
            AuthorId = user!.Id,
            CreatedAt = DateTime.UtcNow
        };
        _db.Announcements.Add(announcement);
        await _db.SaveChangesAsync();

        // Redirect to Details — this is where the payload will execute
        return RedirectToAction(nameof(Details), new { id = announcement.Id });
    }
}
