using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using SafeVault.Services;
using Microsoft.Data.Sqlite;
using System.ComponentModel.DataAnnotations;

namespace SafeVault.Pages
{
    /// <summary>
    /// INTENTIONALLY VULNERABLE PAGE MODEL FOR ACTIVITY 3 DEMONSTRATION
    /// This page model contains common security vulnerabilities for educational purposes
    /// DO NOT USE IN PRODUCTION
    /// </summary>
    public class VulnerableDemoModel : PageModel
    {
        private readonly SafeVaultDbContext _context;
        private readonly ILogger<VulnerableDemoModel> _logger;

        public VulnerableDemoModel(SafeVaultDbContext context, ILogger<VulnerableDemoModel> logger)
        {
            _context = context;
            _logger = logger;
        }

        [BindProperty]
        public string Username { get; set; } = string.Empty;

        [BindProperty]
        public string Email { get; set; } = string.Empty;

        [BindProperty]
        public string Bio { get; set; } = string.Empty;

        [BindProperty]
        public string SearchTerm { get; set; } = string.Empty;

        [BindProperty]
        public string IsAdmin { get; set; } = "false";

        public string? ErrorMessage { get; set; }
        public string? SuccessMessage { get; set; }
        public string? UserInput { get; set; }
        public string? UserBio { get; set; }
        public List<Pages.UserSearchResult>? SearchResults { get; set; }

        public void OnGet()
        {
            // Initialize page
        }

        public async Task<IActionResult> OnPostAsync(string action)
        {
            try
            {
                switch (action?.ToLower())
                {
                    case "register":
                        return await HandleRegister();
                    case "search":
                        return await HandleSearch();
                    case "test":
                        return await HandleTestXSS();
                    default:
                        ErrorMessage = "Invalid action specified.";
                        return Page();
                }
            }
            catch (Exception ex)
            {
                // VULNERABILITY: Information disclosure in error messages
                ErrorMessage = $"<div class='alert alert-danger'>Database Error: {ex.Message}<br>Stack Trace: {ex.StackTrace}</div>";
                _logger.LogError(ex, "Error in vulnerable demo page");
                return Page();
            }
        }

        private async Task<IActionResult> HandleRegister()
        {
            // Simulate async operation
            await Task.Delay(50);
            
            // VULNERABILITY: No input validation or sanitization
            if (string.IsNullOrEmpty(Username) || string.IsNullOrEmpty(Email))
            {
                ErrorMessage = "<script>alert('Username and Email are required!');</script><div class='text-danger'>Please fill in all required fields.</div>";
                return Page();
            }

            // VULNERABILITY: Check for admin privilege escalation
            if (IsAdmin == "true")
            {
                SuccessMessage = $"<div class='alert alert-success'><strong>ADMIN USER CREATED!</strong> Welcome <em>{Username}</em>! You now have administrative privileges.</div>";
                UserInput = Username;
                UserBio = Bio;
                return Page();
            }

            // Simulate user creation (vulnerable to XSS in success message)
            UserInput = Username;
            UserBio = Bio;
            SuccessMessage = "User registered successfully!";
            
            return Page();
        }

        private async Task<IActionResult> HandleSearch()
        {
            if (string.IsNullOrEmpty(SearchTerm))
            {
                ErrorMessage = "Search term is required.";
                return Page();
            }

            try
            {
                // VULNERABILITY: For demonstration, we'll simulate SQL injection vulnerability
                // In a real scenario, this would connect to the actual database unsafely
                
                // Simulate async database operation
                await Task.Delay(100); // Simulate database query delay
                
                _logger.LogWarning("Executing vulnerable search with term: {SearchTerm}", SearchTerm);

                // Simulate vulnerable database query results
                SearchResults = new List<Pages.UserSearchResult>();
                
                // Add demo results that would come from a real database
                if (SearchTerm.Contains("admin") || SearchTerm.Contains("'"))
                {
                    SearchResults.Add(new Pages.UserSearchResult
                    {
                        Id = 1,
                        Username = "admin",
                        Email = "admin@demo.com"
                    });
                    SearchResults.Add(new Pages.UserSearchResult
                    {
                        Id = 2,
                        Username = "demo_user", 
                        Email = "user@demo.com"
                    });
                }
                else if (SearchTerm.ToLower().Contains("demo") || SearchTerm.ToLower().Contains("user"))
                {
                    SearchResults.Add(new Pages.UserSearchResult
                    {
                        Id = 2,
                        Username = "demo_user",
                        Email = "user@demo.com"
                    });
                }

                if (!SearchResults.Any())
                {
                    ErrorMessage = $"<div class='alert alert-info'>No users found matching '<strong>{SearchTerm}</strong>'. Try searching for: <em>admin</em>, <em>demo</em>, or try SQL injection like <code>' OR 1=1 --</code></div>";
                }
                else
                {
                    // Demonstrate that SQL injection "worked" by showing all users
                    if (SearchTerm.Contains("'") || SearchTerm.Contains("--") || SearchTerm.Contains("OR"))
                    {
                        ErrorMessage = $"<div class='alert alert-danger'><strong>SQL Injection Detected!</strong> The search term '<code>{SearchTerm}</code>' appears to be a SQL injection attempt. In a vulnerable system, this could expose all user data!</div>";
                    }
                }
            }
            catch (Exception ex)
            {
                // VULNERABILITY: Detailed error information disclosure
                ErrorMessage = $"<div class='alert alert-danger'><strong>SQL Error:</strong> {ex.Message}<br><small>Query: {SearchTerm}</small></div>";
                _logger.LogError(ex, "SQL error during vulnerable search");
            }

            return Page();
        }

        private async Task<IActionResult> HandleTestXSS()
        {
            // Simulate async operation
            await Task.Delay(50);
            
            // VULNERABILITY: Intentionally create XSS payload for demonstration
            var xssPayload = "<script>alert('XSS Vulnerability Detected!');</script><div style='background:red;color:white;padding:10px;'>This content was injected via XSS!</div>";
            
            ErrorMessage = $"<div class='alert alert-warning'>XSS Test Executed:<br>{xssPayload}</div>";
            UserInput = "Test User";
            UserBio = xssPayload;
            
            return Page();
        }
    }
}

namespace SafeVault.Pages
{
    public class UserSearchResult
    {
        public int Id { get; set; }
        public string Username { get; set; } = string.Empty;
        public string Email { get; set; } = string.Empty;
    }
}
