// ============================================================
// SecureFileUploadService.cs — Remediation for Vulnerability #7
// ============================================================
// OWASP A01 — Broken Access Control (remediated)
//
// Three controls are applied here to address the flaws in the
// vulnerable implementation:
//
// 1. EXTENSION WHITELIST (IsAllowed)
//    Only known safe document and image formats are permitted.
//    The check uses case-insensitive comparison so ".PDF" and ".pdf"
//    are treated the same. Any file not on the list is rejected before
//    it reaches SaveAsync().
//
// 2. GUID FILENAME (SaveAsync)
//    The original filename is never used on disk. A new GUID is generated
//    for each upload and combined with only the file extension (validated
//    above). This eliminates path traversal risk and prevents filename
//    guessing attacks on stored files.
//
// 3. AUTHENTICATED DOWNLOAD (ExpensesController.Download)
//    Files are still written to wwwroot/uploads/ (UseStaticFiles serves
//    this directory), BUT the stored name is a GUID — nobody can guess it
//    from the original filename. In Secure mode the expense detail view
//    links to /Expenses/Download/{attachmentId}, which checks ownership
//    before streaming the file, rather than linking to /uploads/<name>.
//
// Registered in DI by Program.cs when ASPNETCORE_ENVIRONMENT=Secure.
// ============================================================

namespace Portal.Web.Services;

public class SecureFileUploadService : IFileUploadService
{
    // Whitelist of permitted extensions — case-insensitive via the comparer
    private static readonly HashSet<string> Allowed = new(StringComparer.OrdinalIgnoreCase)
    {
        ".pdf", ".jpg", ".jpeg", ".png", ".doc", ".docx"
    };

    // SECURE: reject anything not explicitly on the whitelist
    public bool IsAllowed(IFormFile file) => Allowed.Contains(Path.GetExtension(file.FileName));

    public async Task<(string storedFileName, string originalFileName)> SaveAsync(IFormFile file, string uploadsDir)
    {
        // Extract only the extension from the client-supplied filename.
        // We validated the extension is safe in IsAllowed(), but we never
        // use the filename itself — only the extension is kept.
        var ext = Path.GetExtension(file.FileName);

        // SECURE: generate a random name — eliminates path traversal and guessing.
        // e.g. "3f7ab2c1-9e4d-4f0a-b2e3-1a2b3c4d5e6f.pdf"
        var stored = $"{Guid.NewGuid()}{ext}";
        var path = Path.Combine(uploadsDir, stored);

        await using var stream = new FileStream(path, FileMode.Create);
        await file.CopyToAsync(stream);

        // Return both names: stored (GUID) is what's on disk;
        // original is the display name shown to the user and used
        // as the download filename in ExpensesController.Download().
        return (stored, file.FileName);
    }
}
