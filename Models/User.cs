using System.ComponentModel.DataAnnotations;
using System.Text.RegularExpressions;

namespace SafeVault.Models
{
    /// <summary>
    /// User model with comprehensive validation to prevent malicious input
    /// Includes authentication and authorization support
    /// </summary>
    public class User
    {
        public int UserID { get; set; }

        [Required(ErrorMessage = "Username is required")]
        [StringLength(100, MinimumLength = 3, ErrorMessage = "Username must be between 3 and 100 characters")]
        [RegularExpression(@"^[a-zA-Z0-9_.-]+$", ErrorMessage = "Username can only contain letters, numbers, underscores, dots, and hyphens")]
        public string Username { get; set; } = string.Empty;

        [Required(ErrorMessage = "Email is required")]
        [EmailAddress(ErrorMessage = "Invalid email format")]
        [StringLength(100, ErrorMessage = "Email cannot exceed 100 characters")]
        public string Email { get; set; } = string.Empty;

        /// <summary>
        /// Hashed password - never store plain text passwords
        /// </summary>
        [Required(ErrorMessage = "Password is required")]
        public string PasswordHash { get; set; } = string.Empty;

        /// <summary>
        /// User role for authorization (Admin, User, etc.)
        /// </summary>
        [Required(ErrorMessage = "Role is required")]
        [StringLength(50, ErrorMessage = "Role cannot exceed 50 characters")]
        public string Role { get; set; } = "User";

        /// <summary>
        /// Account creation timestamp
        /// </summary>
        public DateTime CreatedAt { get; set; } = DateTime.UtcNow;

        /// <summary>
        /// Last login timestamp
        /// </summary>
        public DateTime? LastLoginAt { get; set; }

        /// <summary>
        /// Account status (Active, Locked, Suspended)
        /// </summary>
        public string Status { get; set; } = "Active";

        /// <summary>
        /// Failed login attempts counter
        /// </summary>
        public int FailedLoginAttempts { get; set; } = 0;

        /// <summary>
        /// Additional validation for username to prevent potential security issues
        /// </summary>
        public static bool IsValidUsername(string username)
        {
            if (string.IsNullOrWhiteSpace(username))
                return false;

            // Check for dangerous patterns that could indicate injection attempts
            var dangerousPatterns = new[]
            {
                "<script", "</script>", "javascript:", "vbscript:", "onload=", "onerror=",
                "eval(", "document.cookie", "document.write", "innerHTML", "outerHTML",
                "SELECT", "INSERT", "UPDATE", "DELETE", "DROP", "EXEC", "UNION",
                "--", "/*", "*/", "xp_", "sp_"
            };

            var upperUsername = username.ToUpperInvariant();
            return !dangerousPatterns.Any(pattern => upperUsername.Contains(pattern.ToUpperInvariant()));
        }

        /// <summary>
        /// Validates password strength and security requirements
        /// </summary>
        public static bool IsValidPassword(string password)
        {
            if (string.IsNullOrWhiteSpace(password))
                return false;

            // Password must be at least 8 characters long
            if (password.Length < 8)
                return false;

            // Must contain at least one uppercase letter
            if (!password.Any(char.IsUpper))
                return false;

            // Must contain at least one lowercase letter
            if (!password.Any(char.IsLower))
                return false;

            // Must contain at least one digit
            if (!password.Any(char.IsDigit))
                return false;

            // Must contain at least one special character
            var specialChars = "!@#$%^&*()_+-=[]{}|;:,.<>?";
            if (!password.Any(c => specialChars.Contains(c)))
                return false;

            return true;
        }

        /// <summary>
        /// Validates user role
        /// </summary>
        public static bool IsValidRole(string role)
        {
            var validRoles = new[] { "User", "Admin", "Moderator" };
            return validRoles.Contains(role, StringComparer.OrdinalIgnoreCase);
        }

        /// <summary>
        /// Additional validation for email to prevent XSS and injection
        /// </summary>
        public static bool IsValidEmail(string email)
        {
            if (string.IsNullOrWhiteSpace(email))
                return false;

            // Basic email format validation using regex
            var emailRegex = new Regex(@"^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$");
            if (!emailRegex.IsMatch(email))
                return false;

            // Check for dangerous patterns
            var dangerousPatterns = new[]
            {
                "<", ">", "\"", "'", "&", "javascript:", "data:", "vbscript:"
            };

            return !dangerousPatterns.Any(pattern => email.Contains(pattern));
        }
    }
}
