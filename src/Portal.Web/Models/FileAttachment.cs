namespace Portal.Web.Models;

public class FileAttachment
{
    public int Id { get; set; }
    public int ExpenseReportId { get; set; }
    public ExpenseReport ExpenseReport { get; set; } = null!;
    public string OriginalFileName { get; set; } = string.Empty;
    public string StoredFileName { get; set; } = string.Empty;
    public DateTime UploadedAt { get; set; } = DateTime.UtcNow;
}
