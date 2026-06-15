using System.ComponentModel.DataAnnotations;

namespace Portal.Web.Models.ViewModels;

public class AnnouncementCreateViewModel
{
    [Required, MaxLength(200)]
    public string Title { get; set; } = string.Empty;

    [Required]
    public string Content { get; set; } = string.Empty;
}
