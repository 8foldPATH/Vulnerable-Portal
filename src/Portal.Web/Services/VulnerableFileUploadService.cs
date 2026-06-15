// ============================================================
// VulnerableFileUploadService.cs — VULNERABILITY #7: Insecure File Upload
// ============================================================
// OWASP A01 — Broken Access Control
//
// Three distinct flaws are present here:
//
// 1. NO FILE TYPE VALIDATION
//    IsAllowed() always returns true. Any file — .html, .php, .exe,
//    .bat — is accepted and stored. An attacker can upload a phishing
//    page (login.html) or any other malicious content.
//
// 2. ORIGINAL FILENAME USED VERBATIM
//    The filename sent by the browser is used directly in Path.Combine().
//    This creates a path traversal risk: a filename like "../../appsettings.json"
//    would attempt to write outside wwwroot/uploads/. The OS may block
//    it depending on permissions, but the application itself has no defence.
//
// 3. FILES STORED IN wwwroot/uploads/ WITHOUT AUTHENTICATION
//    UseStaticFiles() in Program.cs serves the entire wwwroot directory
//    to anonymous requests. Anything uploaded lands at /uploads/<filename>
//    and is immediately publicly accessible — no login required.
//
// Registered in DI by Program.cs when the environment is NOT "Secure".
// Compare with SecureFileUploadService which addresses all three flaws.
// ============================================================

namespace Portal.Web.Services;

public class VulnerableFileUploadService : IFileUploadService
{
    // VULNERABLE: no validation at all — every file type is permitted
    public bool IsAllowed(IFormFile file) => true;

    public async Task<(string storedFileName, string originalFileName)> SaveAsync(IFormFile file, string uploadsDir)
    {
        // VULNERABLE: use the filename provided by the browser without sanitisation.
        // The browser sends the original filename in the Content-Disposition header.
        // An attacker controls this value and can set it to anything, including
        // paths with directory traversal sequences (../../).
        var original = file.FileName;

        // VULNERABLE: Path.Combine with an unsanitised filename.
        // On most systems Path.Combine handles absolute paths by discarding the
        // base, but relative paths with ../ can escape the uploads directory.
        var path = Path.Combine(uploadsDir, original);

        // File written to wwwroot/uploads/<original-filename>
        // UseStaticFiles() will serve this at /uploads/<original-filename>
        // with no authentication check.
        await using var stream = new FileStream(path, FileMode.Create);
        await file.CopyToAsync(stream);

        // Return the same name for both stored and original — the file is
        // referenced by its original name in the attachment link on the expense page
        return (original, original);
    }
}
