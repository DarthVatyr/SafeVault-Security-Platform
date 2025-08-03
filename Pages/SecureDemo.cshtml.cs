using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using SafeVault.Services;
using System.ComponentModel.DataAnnotations;
using System.Text.RegularExpressions;
using Microsoft.EntityFrameworkCore;

namespace SafeVault.Pages
{
    /// <summary>
    /// SECURE PAGE MODEL - DEMONSTRATES FIXED VULNERABILITIES FOR ACTIVITY 3
    /// This page model shows proper security implementations
    /// </summary>
    [ValidateAntiForgeryToken]
    public class SecureDemoModel : PageModel
    {
        private readonly SafeVaultDbContext _context;
        private readonly InputValidationService _validationService;
        private readonly ILogger<SecureDemoModel> _logger;

        public SecureDemoModel(SafeVaultDbContext context, InputValidationService validationService, ILogger<SecureDemoModel> logger)
        {
            _context = context;
            _validationService = validationService;
            _logger = logger;
        }

        [BindProperty]
        [Required]
        [StringLength(50, MinimumLength = 3)]
        [RegularExpression(@"^[a-zA-Z0-9_]+$", ErrorMessage = "Username can only contain letters, numbers, and underscores")]
        public string Username { get; set; } = string.Empty;

        [BindProperty]
        [Required]
        [EmailAddress]
        public string Email { get; set; } = string.Empty;

        [BindProperty]
        [StringLength(500)]
        public string Bio { get; set; } = string.Empty;

        [BindProperty]
        [StringLength(100)]
        public string SearchTerm { get; set; } = string.Empty;

        public string? ErrorMessage { get; set; }
        public string? SuccessMessage { get; set; }
        public string? UserInput { get; set; }
        public string? UserBio { get; set; }
        public List<Pages.UserSearchResult>? SearchResults { get; set; }
        public List<string>? ValidationErrors { get; set; }

        public void OnGet()
        {
            // Initialize page - no action needed
        }

        public async Task<IActionResult> OnPostAsync(string action)
        {
            try
            {
                switch (action?.ToLower())
                {
                    case "register":
                        return await HandleSecureRegister();
                    case "search":
                        return await HandleSecureSearch();
                    default:
                        ErrorMessage = "Invalid action specified.";
                        return Page();
                }
            }
            catch (Exception ex)
            {
                // FIXED: Generic error message, no information disclosure
                ErrorMessage = "An error occurred while processing your request. Please try again.";
                _logger.LogError(ex, "Error in secure demo page for action {Action}", action);
                return Page();
            }
        }

        private async Task<IActionResult> HandleSecureRegister()
        {
            // Simulate async validation operation
            await Task.Delay(50);
            
            ValidationErrors = new List<string>();

            // FIXED: Comprehensive input validation
            if (!ModelState.IsValid)
            {
                foreach (var error in ModelState.Values.SelectMany(v => v.Errors))
                {
                    ValidationErrors.Add(error.ErrorMessage);
                }
                return Page();
            }

            // FIXED: Use validation service for additional security checks
            var usernameValidation = InputValidationService.ValidateUsername(Username);
            if (!usernameValidation.IsValid)
            {
                ValidationErrors.Add(usernameValidation.ErrorMessage);
            }

            var emailValidation = InputValidationService.ValidateEmail(Email);
            if (!emailValidation.IsValid)
            {
                ValidationErrors.Add(emailValidation.ErrorMessage);
            }

            // FIXED: Check for malicious input patterns
            if (!InputValidationService.IsInputSafe(Username))
            {
                ValidationErrors.Add("Username contains potentially unsafe characters.");
            }

            if (!InputValidationService.IsInputSafe(Email))
            {
                ValidationErrors.Add("Email contains potentially unsafe characters.");
            }

            if (!InputValidationService.IsInputSafe(Bio))
            {
                ValidationErrors.Add("Bio contains potentially unsafe content.");
            }

            if (ValidationErrors.Any())
            {
                return Page();
            }

            // FIXED: Sanitize input before processing
            var sanitizedUsername = InputValidationService.SanitizeInput(Username);
            var sanitizedEmail = InputValidationService.SanitizeInput(Email);
            var sanitizedBio = InputValidationService.SanitizeInput(Bio);

            // Simulate successful user creation
            UserInput = sanitizedUsername;
            UserBio = sanitizedBio;
            SuccessMessage = "User registered successfully! All input has been validated and sanitized.";
            
            _logger.LogInformation("Secure user registration completed for username length: {Length}", sanitizedUsername.Length);
            
            return Page();
        }

        private async Task<IActionResult> HandleSecureSearch()
        {
            if (string.IsNullOrWhiteSpace(SearchTerm))
            {
                ErrorMessage = "Search term is required.";
                return Page();
            }

            // FIXED: Input validation before search
            if (!InputValidationService.IsInputSafe(SearchTerm))
            {
                ErrorMessage = "Search term contains potentially unsafe characters.";
                return Page();
            }

            try
            {
                // FIXED: Use parameterized queries via Entity Framework
                var sanitizedSearchTerm = InputValidationService.SanitizeInput(SearchTerm);
                
                SearchResults = await _context.Users
                    .Where(u => u.Username.Contains(sanitizedSearchTerm) || u.Email.Contains(sanitizedSearchTerm))
                    .Select(u => new Pages.UserSearchResult
                    {
                        Id = u.UserID,
                        Username = u.Username,
                        Email = u.Email
                    })
                    .Take(10) // FIXED: Limit results to prevent performance issues
                    .ToListAsync();

                if (!SearchResults.Any())
                {
                    ErrorMessage = $"No users found matching your search criteria.";
                }

                _logger.LogInformation("Secure search completed. Found {Count} results", SearchResults?.Count ?? 0);
            }
            catch (Exception ex)
            {
                // FIXED: Generic error message, log details securely
                ErrorMessage = "An error occurred during search. Please try again.";
                _logger.LogError(ex, "Error during secure search with term length: {Length}", SearchTerm?.Length ?? 0);
            }

            return Page();
        }
    }
}
