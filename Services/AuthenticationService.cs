using Microsoft.EntityFrameworkCore;
using SafeVault.Models;
using BCrypt.Net;

namespace SafeVault.Services
{
    /// <summary>
    /// Secure authentication service with password hashing and login verification
    /// </summary>
    public class AuthenticationService
    {
        private readonly SafeVaultDbContext _context;
        private readonly ILogger<AuthenticationService> _logger;
        private const int MaxFailedAttempts = 5;
        private const int LockoutDurationMinutes = 30;

        public AuthenticationService(SafeVaultDbContext context, ILogger<AuthenticationService> logger)
        {
            _context = context;
            _logger = logger;
        }

        /// <summary>
        /// Securely hashes a password using BCrypt
        /// </summary>
        public string HashPassword(string password)
        {
            if (string.IsNullOrWhiteSpace(password))
                throw new ArgumentException("Password cannot be null or empty", nameof(password));

            // Use BCrypt with cost factor 12 for good security/performance balance
            return BCrypt.Net.BCrypt.HashPassword(password, 12);
        }

        /// <summary>
        /// Verifies a password against a hash
        /// </summary>
        public bool VerifyPassword(string password, string hash)
        {
            if (string.IsNullOrWhiteSpace(password) || string.IsNullOrWhiteSpace(hash))
                return false;

            try
            {
                return BCrypt.Net.BCrypt.Verify(password, hash);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error verifying password");
                return false;
            }
        }

        /// <summary>
        /// Authenticates a user with username and password
        /// </summary>
        public async Task<(bool Success, string Message, User? User)> AuthenticateUserAsync(string username, string password)
        {
            try
            {
                // Input validation
                if (string.IsNullOrWhiteSpace(username) || string.IsNullOrWhiteSpace(password))
                {
                    _logger.LogWarning("Authentication attempt with empty username or password");
                    return (false, "Username and password are required", null);
                }

                // Sanitize input
                var sanitizedUsername = InputValidationService.SanitizeInput(username);

                // Find user by username
                var user = await _context.Users
                    .Where(u => u.Username == sanitizedUsername)
                    .FirstOrDefaultAsync();

                if (user == null)
                {
                    _logger.LogWarning("Authentication attempt for non-existent user: {Username}", sanitizedUsername);
                    // Return generic message to prevent username enumeration
                    return (false, "Invalid username or password", null);
                }

                // Check if account is locked
                if (user.Status == "Locked")
                {
                    _logger.LogWarning("Authentication attempt for locked account: {Username}", sanitizedUsername);
                    return (false, "Account is locked due to too many failed login attempts", null);
                }

                // Verify password
                if (!VerifyPassword(password, user.PasswordHash))
                {
                    // Increment failed attempts
                    user.FailedLoginAttempts++;
                    
                    // Lock account if too many failed attempts
                    if (user.FailedLoginAttempts >= MaxFailedAttempts)
                    {
                        user.Status = "Locked";
                        _logger.LogWarning("Account locked due to too many failed attempts: {Username}", sanitizedUsername);
                    }

                    await _context.SaveChangesAsync();
                    _logger.LogWarning("Failed authentication attempt for user: {Username}", sanitizedUsername);
                    return (false, "Invalid username or password", null);
                }

                // Successful authentication
                user.FailedLoginAttempts = 0; // Reset failed attempts
                user.LastLoginAt = DateTime.UtcNow;
                await _context.SaveChangesAsync();

                _logger.LogInformation("Successful authentication for user: {Username}", sanitizedUsername);
                return (true, "Authentication successful", user);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error during authentication for user: {Username}", username);
                return (false, "An error occurred during authentication", null);
            }
        }

        /// <summary>
        /// Registers a new user with secure password hashing
        /// </summary>
        public async Task<(bool Success, string Message, User? User)> RegisterUserAsync(string username, string email, string password, string role = "User")
        {
            try
            {
                // Validate inputs
                var validation = InputValidationService.ValidateUserInput(username, email);
                if (!validation.IsValid)
                {
                    var errors = string.Join(", ", validation.Errors.Values);
                    _logger.LogWarning("User registration failed due to validation errors: {Errors}", errors);
                    return (false, errors, null);
                }

                if (!User.IsValidPassword(password))
                {
                    return (false, "Password must be at least 8 characters long and contain uppercase, lowercase, digit, and special character", null);
                }

                if (!User.IsValidRole(role))
                {
                    return (false, "Invalid role specified", null);
                }

                // Sanitize inputs
                var sanitizedUsername = InputValidationService.SanitizeInput(username);
                var sanitizedEmail = InputValidationService.SanitizeInput(email);

                // Check if user already exists
                var existingUser = await _context.Users
                    .Where(u => u.Username == sanitizedUsername || u.Email == sanitizedEmail)
                    .FirstOrDefaultAsync();

                if (existingUser != null)
                {
                    _logger.LogWarning("Attempt to register user with existing username or email: {Username}, {Email}", 
                        sanitizedUsername, sanitizedEmail);
                    return (false, "Username or email already exists", null);
                }

                // Hash password
                var passwordHash = HashPassword(password);

                // Create new user
                var newUser = new User
                {
                    Username = sanitizedUsername,
                    Email = sanitizedEmail,
                    PasswordHash = passwordHash,
                    Role = role,
                    CreatedAt = DateTime.UtcNow,
                    Status = "Active"
                };

                _context.Users.Add(newUser);
                await _context.SaveChangesAsync();

                _logger.LogInformation("Successfully registered new user: {Username}", sanitizedUsername);
                return (true, "User registered successfully", newUser);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error during user registration for username: {Username}", username);
                return (false, "An error occurred during registration", null);
            }
        }

        /// <summary>
        /// Unlocks a user account (admin function)
        /// </summary>
        public async Task<(bool Success, string Message)> UnlockUserAccountAsync(string username)
        {
            try
            {
                var sanitizedUsername = InputValidationService.SanitizeInput(username);
                
                var user = await _context.Users
                    .Where(u => u.Username == sanitizedUsername)
                    .FirstOrDefaultAsync();

                if (user == null)
                {
                    return (false, "User not found");
                }

                user.Status = "Active";
                user.FailedLoginAttempts = 0;
                await _context.SaveChangesAsync();

                _logger.LogInformation("Account unlocked for user: {Username}", sanitizedUsername);
                return (true, "Account unlocked successfully");
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error unlocking account for user: {Username}", username);
                return (false, "An error occurred while unlocking the account");
            }
        }
    }
}
