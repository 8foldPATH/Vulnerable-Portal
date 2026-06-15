// ============================================================
// ProfileController.cs — Contains Vulnerabilities #6 and #9
// ============================================================
// VULNERABILITY #6 — Mass Assignment / Privilege Escalation (OWASP A08)
//   The Edit POST action uses a DTO (ProfileEditViewModel) that only
//   exposes FullName and Department. However, in Vulnerable mode the
//   action also reads IsHrManager directly from Request.Form — raw HTTP
//   POST data. A user can inject &IsHrManager=true into the request body
//   using browser DevTools or curl, elevating their own privileges without
//   admin involvement.
//   Fix: in Secure mode, the action only reads from the DTO. IsHrManager
//   is not in the DTO, so it is never touched regardless of what is POSTed.
//
// VULNERABILITY #9 — Sensitive Data Exposed via URL (OWASP A02/A09)
//   The Index action accepts a userId query parameter and returns any
//   user's profile without checking whether the caller is that user.
//   Additionally, the accessed userId is written to the application log
//   in plaintext — an attacker with log access can enumerate which accounts
//   were accessed and harvest user IDs for use in other attacks.
//   Fix: in Secure mode, the userId parameter is ignored and the action
//   always returns the current user's own profile. No IDs are logged.
// ============================================================

using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Portal.Web.Configuration;
using Portal.Web.Models;
using Portal.Web.Models.ViewModels;

namespace Portal.Web.Controllers;

[Authorize]
public class ProfileController : Controller
{
    private readonly UserManager<ApplicationUser> _userManager;
    private readonly SecurityProfile _profile;
    private readonly ILogger<ProfileController> _logger;

    public ProfileController(
        UserManager<ApplicationUser> userManager,
        SecurityProfile profile,
        ILogger<ProfileController> logger)
    {
        _userManager = userManager;
        _profile = profile;
        _logger = logger;
    }

    // GET /Profile or GET /Profile?userId=<id>
    public async Task<IActionResult> Index(string? userId)
    {
        ApplicationUser? user;

        // -------------------------------------------------------
        // VULNERABILITY #9 — Sensitive Data Exposed via URL
        // -------------------------------------------------------
        // In Vulnerable mode: if userId is provided, look up that user
        // and return their profile — no check that this matches the caller.
        // Any authenticated user can read any other user's profile by
        // passing their ID in the query string.
        //
        // The ID can be obtained from:
        //   - /Admin (unauthenticated in Vulnerable mode — Vulnerability #3)
        //   - The Employee Directory table (IDs shown in Vulnerable mode)
        //   - Enumerating integer IDs (Identity uses GUIDs, so this requires
        //     the above sources first)
        if (_profile.IsVulnerable && !string.IsNullOrEmpty(userId))
        {
            user = await _userManager.FindByIdAsync(userId);

            // LOG LEAKAGE: writing the userId to the log file exposes it to
            // anyone with log access (developers, ops, SIEM, log aggregators).
            // In a real breach scenario, log data is often captured by attackers.
            // Structured logging with {UserId} also means the ID ends up in
            // any downstream log analytics tools.
            _logger.LogInformation("Profile viewed: userId={UserId} requested by {Requester}",
                userId, User.Identity?.Name);

            // Tell the view that we're peeking at someone else's profile
            // (used to display the red "Not your account" warning)
            ViewBag.PeekedUserId = userId;
        }
        else
        {
            // SECURE behaviour (and default for unauthenticated or no userId):
            // always return the current user's own profile.
            // GetUserAsync reads the user ID from the claims principal — it
            // never touches request parameters.
            user = await _userManager.GetUserAsync(User);
        }

        if (user == null) return NotFound();
        return View(user);
    }

    // GET /Profile/Edit — show the edit form populated with current values
    [HttpGet]
    public async Task<IActionResult> Edit()
    {
        var user = await _userManager.GetUserAsync(User);
        if (user == null) return NotFound();

        // ProfileEditViewModel intentionally does NOT include IsHrManager.
        // In Secure mode this means the field can never be set via this form.
        // In Vulnerable mode we bypass this DTO restriction by reading from Request.Form below.
        return View(new ProfileEditViewModel
        {
            FullName = user.FullName,
            Department = user.Department
        });
    }

    // POST /Profile/Edit — save updated profile details
    [HttpPost, ValidateAntiForgeryToken]
    public async Task<IActionResult> Edit(ProfileEditViewModel model)
    {
        if (!ModelState.IsValid) return View(model);

        var user = await _userManager.GetUserAsync(User);
        if (user == null) return NotFound();

        // Fields in the DTO are always updated — safe in both modes
        user.FullName = model.FullName;
        user.Department = model.Department;

        // -------------------------------------------------------
        // VULNERABILITY #6 — Mass Assignment / Privilege Escalation
        // -------------------------------------------------------
        // In Vulnerable mode: read IsHrManager directly from the raw HTTP
        // form body. Even though the edit form doesn't render this field,
        // a user can add it to the POST body manually:
        //
        //   Using browser DevTools → Network → Edit and Resend:
        //     Append &IsHrManager=true to the request body
        //
        //   Using curl:
        //     -d "FullName=...&Department=...&IsHrManager=true&__RequestVerificationToken=..."
        //
        // The server accepts and persists this extra field, promoting the user
        // to HR Manager without any admin action.
        if (_profile.IsVulnerable)
        {
            // Request.Form["IsHrManager"] reads directly from the POST body.
            // A checkbox value arrives as "true,false" (browser sends hidden + checkbox);
            // a manually injected value arrives as "true". StartsWith handles both.
            var raw = Request.Form["IsHrManager"].ToString();
            if (raw.StartsWith("true", StringComparison.OrdinalIgnoreCase))
                user.IsHrManager = true;
            else if (raw.StartsWith("false", StringComparison.OrdinalIgnoreCase))
                user.IsHrManager = false;
        }
        // SECURE mode: IsHrManager is not in ProfileEditViewModel, so the model
        // binder never populates it. Request.Form is not read directly.
        // The field on the user object is left exactly as it was — only an
        // admin action (not implemented here) would be able to change it.

        await _userManager.UpdateAsync(user);
        TempData["Success"] = "Profile updated successfully.";
        return RedirectToAction(nameof(Index));
    }
}
