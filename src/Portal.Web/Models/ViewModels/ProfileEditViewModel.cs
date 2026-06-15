// ============================================================
// ProfileEditViewModel.cs — DTO for the profile edit form
// ============================================================
// This is the remediation for Vulnerability #6 (Mass Assignment).
//
// The problem: if the Edit action bound directly to ApplicationUser,
// every field on the model — including IsHrManager, the role flag —
// would be eligible for assignment from form data. An attacker could
// POST &IsHrManager=true to promote themselves.
//
// The fix: use a dedicated ViewModel (DTO) that only exposes the fields
// a user is permitted to change. IsHrManager is intentionally ABSENT.
// The ASP.NET Core model binder will only populate properties it finds on
// this class — anything else in the POST body is silently ignored.
//
// In Vulnerable mode, ProfileController works around this by reading
// IsHrManager directly from Request.Form, bypassing the DTO safety.
// In Secure mode, that bypass is disabled and only these two fields
// are ever updated.
// ============================================================

using System.ComponentModel.DataAnnotations;

namespace Portal.Web.Models.ViewModels;

public class ProfileEditViewModel
{
    [Required, MaxLength(100), Display(Name = "Full name")]
    public string FullName { get; set; } = string.Empty;

    [Required, MaxLength(100)]
    public string Department { get; set; } = string.Empty;

    // IsHrManager is deliberately NOT here — this omission is the security control.
    // The model binder will reject any IsHrManager value in the POST body.
}
