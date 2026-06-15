// ============================================================
// ApplicationUser.cs — Custom user model extending ASP.NET Identity
// ============================================================
// IdentityUser provides the built-in Identity fields:
//   Id, UserName, Email, PasswordHash, SecurityStamp, etc.
//
// We extend it with three additional properties stored as columns
// in the AspNetUsers table (EF Core adds them automatically):
//
//   FullName   — display name shown throughout the portal UI
//   Department — used in the employee directory and admin panel
//   IsHrManager — the target of the Mass Assignment attack (Vulnerability #6)
//
// IsHrManager is particularly important for the portfolio demo:
//   - It is NOT rendered in the profile edit form
//   - In Vulnerable mode, ProfileController reads it from raw form data,
//     allowing any user to set it to true by injecting &IsHrManager=true
//   - In Secure mode, only the DTO fields (FullName, Department) are updated;
//     IsHrManager is left unchanged
// ============================================================

using Microsoft.AspNetCore.Identity;

namespace Portal.Web.Models;

public class ApplicationUser : IdentityUser
{
    public string FullName { get; set; } = string.Empty;
    public string Department { get; set; } = string.Empty;

    // Privileged flag — the Mass Assignment target in Vulnerability #6.
    // Should only be settable by an admin; in Vulnerable mode any employee
    // can elevate themselves by injecting this field into a profile edit POST.
    public bool IsHrManager { get; set; }
}
