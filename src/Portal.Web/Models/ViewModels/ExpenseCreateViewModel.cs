using System.ComponentModel.DataAnnotations;

namespace Portal.Web.Models.ViewModels;

public class ExpenseCreateViewModel
{
    [Required, MaxLength(500)]
    public string Description { get; set; } = string.Empty;

    [Required, Range(0.01, 100000, ErrorMessage = "Amount must be between £0.01 and £100,000")]
    [DataType(DataType.Currency), Display(Name = "Amount (£)")]
    public decimal Amount { get; set; }
}
