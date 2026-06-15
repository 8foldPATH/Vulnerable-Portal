namespace Portal.Web.Models;

public class ExpenseReport
{
    public int Id { get; set; }
    public string EmployeeId { get; set; } = string.Empty;
    public ApplicationUser Employee { get; set; } = null!;
    public string Description { get; set; } = string.Empty;
    public decimal Amount { get; set; }
    public string Status { get; set; } = "Pending";
    public DateTime CreatedAt { get; set; } = DateTime.UtcNow;
    public ICollection<FileAttachment> Attachments { get; set; } = new List<FileAttachment>();
}
