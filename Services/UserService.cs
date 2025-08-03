using Microsoft.EntityFrameworkCore;
using SafeVault.Models;
using SafeVault.Services;

namespace SafeVault.Services
{
    /// <summary>
    /// Secure user service that demonstrates protection against SQL injection attacks
    /// Uses Entity Framework Core with parameterized queries for all database operations
    /// </summary>
    public class UserService
    {
        private readonly SafeVaultDbContext _context;
        private readonly ILogger<UserService> _logger;

        public UserService(SafeVaultDbContext context, ILogger<UserService> logger)
        {
            _context = context;
            _logger = logger;
        }

        /// <summary>
        /// Securely creates a new user with parameterized queries
        /// This method is safe from SQL injection attacks
        /// </summary>
        public async Task<(bool Success, string Message, User? User)> CreateUserAsync(string username, string email)
        {
            try
            {
                // Validate input first
                var validation = InputValidationService.ValidateUserInput(username, email);
                if (!validation.IsValid)
                {
                    var errors = string.Join(", ", validation.Errors.Values);
                    _logger.LogWarning("User creation failed due to validation errors: {Errors}", errors);
                    return (false, errors, null);
                }

                // Sanitize input (additional protection)
                var sanitizedUsername = InputValidationService.SanitizeInput(username);
                var sanitizedEmail = InputValidationService.SanitizeInput(email);

                // Check if user already exists (using parameterized query)
                var existingUser = await _context.Users
                    .Where(u => u.Username == sanitizedUsername || u.Email == sanitizedEmail)
                    .FirstOrDefaultAsync();

                if (existingUser != null)
                {
                    _logger.LogWarning("Attempt to create user with existing username or email: {Username}, {Email}", 
                        sanitizedUsername, sanitizedEmail);
                    return (false, "User with this username or email already exists", null);
                }

                // Create new user (Entity Framework automatically uses parameterized queries)
                var newUser = new User
                {
                    Username = sanitizedUsername,
                    Email = sanitizedEmail
                };

                _context.Users.Add(newUser);
                await _context.SaveChangesAsync();

                _logger.LogInformation("Successfully created user: {Username}", sanitizedUsername);
                return (true, "User created successfully", newUser);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error creating user with username: {Username}", username);
                return (false, "An error occurred while creating the user", null);
            }
        }

        /// <summary>
        /// Securely retrieves user by ID using parameterized queries
        /// </summary>
        public async Task<User?> GetUserByIdAsync(int userId)
        {
            try
            {
                // Entity Framework automatically uses parameterized queries
                var user = await _context.Users
                    .Where(u => u.UserID == userId)
                    .FirstOrDefaultAsync();

                return user;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error retrieving user with ID: {UserId}", userId);
                return null;
            }
        }

        /// <summary>
        /// Securely searches for users by username (safe from injection)
        /// </summary>
        public async Task<User?> GetUserByUsernameAsync(string username)
        {
            try
            {
                if (string.IsNullOrWhiteSpace(username))
                    return null;

                // Validate and sanitize input
                var validation = InputValidationService.ValidateUsername(username);
                if (!validation.IsValid)
                {
                    _logger.LogWarning("Invalid username search attempt: {Username}", username);
                    return null;
                }

                var sanitizedUsername = InputValidationService.SanitizeInput(username);

                // Parameterized query through Entity Framework
                var user = await _context.Users
                    .Where(u => u.Username == sanitizedUsername)
                    .FirstOrDefaultAsync();

                return user;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error searching for user by username: {Username}", username);
                return null;
            }
        }

        /// <summary>
        /// Demonstrates a safe search query using Entity Framework (when raw SQL isn't needed)
        /// This is an example of how to safely search when necessary
        /// </summary>
        public async Task<List<User>> SearchUsersAsync(string searchTerm)
        {
            try
            {
                if (string.IsNullOrWhiteSpace(searchTerm))
                    return new List<User>();

                // Validate input
                if (!InputValidationService.IsInputSafe(searchTerm))
                {
                    _logger.LogWarning("Unsafe search term blocked: {SearchTerm}", searchTerm);
                    return new List<User>();
                }

                var sanitizedSearchTerm = InputValidationService.SanitizeInput(searchTerm);

                // SECURE: Using Entity Framework LINQ (automatically parameterized)
                // This is safer than raw SQL and works with all providers including InMemory
                var users = await _context.Users
                    .Where(u => u.Username.Contains(sanitizedSearchTerm) || 
                               u.Email.Contains(sanitizedSearchTerm))
                    .ToListAsync();

                return users;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error searching users with term: {SearchTerm}", searchTerm);
                return new List<User>();
            }
        }

        /// <summary>
        /// Example of what NOT to do - vulnerable to SQL injection
        /// This method is included for educational purposes only and should NEVER be used
        /// </summary>
        [Obsolete("This method is vulnerable to SQL injection and should never be used")]
        public Task<List<User>> UnsafeSearchUsersAsync(string searchTerm)
        {
            // DANGEROUS: This concatenates user input directly into SQL
            // An attacker could inject: '; DROP TABLE Users; --
            // DO NOT USE THIS APPROACH!
            
            /*
            var sql = $"SELECT * FROM Users WHERE Username LIKE '%{searchTerm}%'";
            var users = await _context.Users.FromSqlRaw(sql).ToListAsync();
            return users;
            */
            
            throw new NotImplementedException("This method demonstrates a security vulnerability and should not be implemented");
        }

        /// <summary>
        /// Gets all users with pagination (secure implementation)
        /// </summary>
        public async Task<(List<User> Users, int TotalCount)> GetUsersAsync(int page = 1, int pageSize = 10)
        {
            try
            {
                // Validate pagination parameters
                page = Math.Max(1, page);
                pageSize = Math.Min(Math.Max(1, pageSize), 100); // Limit page size to prevent abuse

                var totalCount = await _context.Users.CountAsync();
                
                var users = await _context.Users
                    .OrderBy(u => u.UserID)
                    .Skip((page - 1) * pageSize)
                    .Take(pageSize)
                    .ToListAsync();

                return (users, totalCount);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error retrieving users with pagination");
                return (new List<User>(), 0);
            }
        }
    }
}
