// ============================================================
// ExpensesController.cs — Contains Vulnerabilities #4 and #7
// ============================================================
// VULNERABILITY #4 — IDOR on expense report details (OWASP A01)
//   Details() fetches a report by its integer ID without verifying
//   that the requesting user owns it. Because IDs are sequential,
//   an attacker logged in as employee1 can enumerate /Expenses/Details/1,
//   /Expenses/Details/2, /Expenses/Details/3 and read every report.
//   Fix: compare report.EmployeeId to the current user's ID; return 403 if
//   they don't match (and the user is not an Admin).
//
// VULNERABILITY #7 — Insecure File Upload (OWASP A01)
//   Upload() delegates to IFileUploadService. In Vulnerable mode that's
//   VulnerableFileUploadService (all types allowed, original filename stored
//   publicly). In Secure mode it's SecureFileUploadService (whitelist,
//   GUID filename). The controller itself doesn't change — the vulnerability
//   lives entirely in the service implementation.
//
//   There is also a Download() action used in Secure mode. In Vulnerable mode
//   the expense detail view links directly to /uploads/<original-filename>
//   (served by UseStaticFiles without auth). In Secure mode the view links
//   to /Expenses/Download/{id} which verifies ownership before streaming.
// ============================================================

using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using Portal.Web.Configuration;
using Portal.Web.Data;
using Portal.Web.Models;
using Portal.Web.Models.ViewModels;
using Portal.Web.Services;

namespace Portal.Web.Controllers;

[Authorize] // All expense actions require login
public class ExpensesController : Controller
{
    private readonly ApplicationDbContext _db;
    private readonly UserManager<ApplicationUser> _userManager;
    private readonly IFileUploadService _fileUpload; // Vulnerable or Secure implementation injected by DI
    private readonly SecurityProfile _profile;
    private readonly IWebHostEnvironment _env;

    public ExpensesController(
        ApplicationDbContext db,
        UserManager<ApplicationUser> userManager,
        IFileUploadService fileUpload,
        SecurityProfile profile,
        IWebHostEnvironment env)
    {
        _db = db;
        _userManager = userManager;
        _fileUpload = fileUpload;
        _profile = profile;
        _env = env;
    }

    // GET /Expenses — list reports belonging to the current user (or all reports for Admin)
    public async Task<IActionResult> Index()
    {
        var userId = _userManager.GetUserId(User);
        IQueryable<ExpenseReport> query = _db.ExpenseReports.Include(e => e.Employee);

        // Admin can see all reports; employees only see their own
        if (!User.IsInRole("Admin"))
            query = query.Where(e => e.EmployeeId == userId);

        var reports = await query.OrderByDescending(e => e.CreatedAt).ToListAsync();
        return View(reports);
    }

    // GET /Expenses/Details/{id} — view a specific report
    public async Task<IActionResult> Details(int id)
    {
        var report = await _db.ExpenseReports
            .Include(e => e.Employee)
            .Include(e => e.Attachments)
            .FirstOrDefaultAsync(e => e.Id == id);

        if (report == null) return NotFound();

        // -------------------------------------------------------
        // VULNERABILITY #4 — IDOR (Insecure Direct Object Reference)
        // -------------------------------------------------------
        // In Vulnerable mode: no ownership check — any authenticated user
        // can read any report by changing the ID in the URL.
        //
        // In Secure mode: we compare the report's EmployeeId (the user who
        // created it) against the currently logged-in user. A mismatch
        // results in 403 Forbidden, unless the caller is an Admin who is
        // permitted to see all reports.
        if (_profile.IsSecure)
        {
            var userId = _userManager.GetUserId(User);
            if (!User.IsInRole("Admin") && report.EmployeeId != userId)
                return Forbid();
        }
        // In Vulnerable mode execution falls through to return View(report)
        // regardless of who submitted the report.

        return View(report);
    }

    // GET /Expenses/Create — show the new expense form
    [HttpGet]
    public IActionResult Create() => View();

    // POST /Expenses/Create — save a new expense report
    [HttpPost, ValidateAntiForgeryToken]
    public async Task<IActionResult> Create(ExpenseCreateViewModel model)
    {
        if (!ModelState.IsValid) return View(model);

        // The EmployeeId is taken from the authenticated session — not from form data.
        // This prevents users from creating reports attributed to other employees.
        var userId = _userManager.GetUserId(User)!;
        var report = new ExpenseReport
        {
            EmployeeId = userId,
            Description = model.Description,
            Amount = model.Amount,
            Status = "Pending",
            CreatedAt = DateTime.UtcNow
        };
        _db.ExpenseReports.Add(report);
        await _db.SaveChangesAsync();
        return RedirectToAction(nameof(Details), new { id = report.Id });
    }

    // POST /Expenses/Upload/{id} — attach a file to an expense report
    [HttpPost, ValidateAntiForgeryToken]
    public async Task<IActionResult> Upload(int id, IFormFile file)
    {
        var report = await _db.ExpenseReports.FindAsync(id);
        if (report == null) return NotFound();

        // In Secure mode also check that the uploader owns this report
        if (_profile.IsSecure)
        {
            var userId = _userManager.GetUserId(User);
            if (!User.IsInRole("Admin") && report.EmployeeId != userId)
                return Forbid();
        }

        if (file == null || file.Length == 0)
        {
            TempData["Error"] = "Please select a file to upload.";
            return RedirectToAction(nameof(Details), new { id });
        }

        // -------------------------------------------------------
        // VULNERABILITY #7 — Insecure File Upload
        // -------------------------------------------------------
        // IsAllowed() delegates to the injected IFileUploadService:
        //   Vulnerable: always returns true — no type checking at all
        //   Secure: checks the extension against a whitelist
        //
        // If the check fails (Secure mode only), we reject the upload here.
        if (!_fileUpload.IsAllowed(file))
        {
            TempData["Error"] = "File type not allowed. Permitted: PDF, JPG, PNG, DOC, DOCX.";
            return RedirectToAction(nameof(Details), new { id });
        }

        // Ensure the uploads directory exists (created on first upload)
        var uploadsDir = Path.Combine(_env.WebRootPath, "uploads");
        Directory.CreateDirectory(uploadsDir);

        // SaveAsync() handles naming and writing:
        //   Vulnerable: uses original filename, writes to wwwroot/uploads/ (public)
        //   Secure: generates a GUID filename, same directory but served via Download()
        var (stored, original) = await _fileUpload.SaveAsync(file, uploadsDir);

        _db.FileAttachments.Add(new FileAttachment
        {
            ExpenseReportId = id,
            OriginalFileName = original, // Display name shown in the UI
            StoredFileName = stored,     // Actual filename on disk (GUID in Secure mode)
            UploadedAt = DateTime.UtcNow
        });
        await _db.SaveChangesAsync();
        TempData["Success"] = "File uploaded successfully.";
        return RedirectToAction(nameof(Details), new { id });
    }

    // GET /Expenses/Download/{attachmentId} — authenticated file download (Secure mode)
    // In Vulnerable mode the view links to /uploads/<filename> via UseStaticFiles instead.
    public async Task<IActionResult> Download(int attachmentId)
    {
        var attachment = await _db.FileAttachments
            .Include(a => a.ExpenseReport)
            .FirstOrDefaultAsync(a => a.Id == attachmentId);

        if (attachment == null) return NotFound();

        // Ownership check — same pattern as Details()
        if (_profile.IsSecure)
        {
            var userId = _userManager.GetUserId(User);
            if (!User.IsInRole("Admin") && attachment.ExpenseReport.EmployeeId != userId)
                return Forbid();
        }

        var path = Path.Combine(_env.WebRootPath, "uploads", attachment.StoredFileName);
        if (!System.IO.File.Exists(path)) return NotFound();

        // PhysicalFile streams the file with the original display name as the download filename
        return PhysicalFile(path, "application/octet-stream", attachment.OriginalFileName);
    }
}
