using System.ComponentModel.DataAnnotations;

namespace UserManagementApi.Models
{
    public class User
    {
        public int Id { get; set; }

        [Required(ErrorMessage = "Name is required")]
        [MinLength(2, ErrorMessage = "Name must be at least 2 characters")]
        public string Name { get; set; } = null!;

        [Required(ErrorMessage = "Email is required")]
        [EmailAddress(ErrorMessage = "Invalid email format")]
        public string Email { get; set; } = null!;
    }
}
