namespace Portal.Web.Services;

public interface IFileUploadService
{
    bool IsAllowed(IFormFile file);
    Task<(string storedFileName, string originalFileName)> SaveAsync(IFormFile file, string uploadsDir);
}
