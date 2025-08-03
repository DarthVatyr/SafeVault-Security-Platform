using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.InMemory;
using Microsoft.Extensions.Logging;
using NUnit.Framework;
using SafeVault.Models;
using SafeVault.Services;

namespace SafeVault.Tests
{
    /// <summary>
    /// Integration tests for UserService to verify SQL injection protection
    /// </summary>
    [TestFixture]
    public class UserServiceSecurityTests
    {
        private SafeVaultDbContext _context = null!;
        private UserService _userService = null!;
        private ILogger<UserService> _logger = null!;

        [SetUp]
        public void Setup()
        {
            // Create in-memory database for testing
            var options = new DbContextOptionsBuilder<SafeVaultDbContext>()
                .UseInMemoryDatabase(databaseName: Guid.NewGuid().ToString())
                .Options;

            _context = new SafeVaultDbContext(options);
            
            // Create a mock logger
            _logger = LoggerFactory.Create(builder => builder.AddConsole())
                .CreateLogger<UserService>();
            
            _userService = new UserService(_context, _logger);

            // Ensure database is created
            _context.Database.EnsureCreated();
        }

        [TearDown]
        public void TearDown()
        {
            _context.Dispose();
        }

        /// <summary>
        /// Test that SQL injection attempts are blocked during user creation
        /// </summary>
        [Test]
        public async Task CreateUserAsync_ProtectsAgainstSQLInjection()
        {
            // Arrange - SQL injection attempts
            var injectionAttempts = new[]
            {
                ("'; DROP TABLE Users; --", "normal@email.com"),
                ("admin'--", "test@test.com"),
                ("' OR '1'='1", "malicious@evil.com"),
                ("normaluser", "'; DELETE FROM Users; --@evil.com"),
                ("user'; UPDATE Users SET Username='hacked' WHERE UserID=1; --", "test@example.com")
            };

            // Act & Assert
            foreach (var (maliciousUsername, maliciousEmail) in injectionAttempts)
            {
                var result = await _userService.CreateUserAsync(maliciousUsername, maliciousEmail);
                
                // Should fail due to validation
                Assert.That(result.Success, Is.False, 
                    $"SQL injection attempt should be blocked: {maliciousUsername}, {maliciousEmail}");
                
                // Verify no user was actually created
                var userCount = await _context.Users.CountAsync();
                Assert.That(userCount, Is.EqualTo(0), 
                    "No users should be created when injection is attempted");
            }
        }

        /// <summary>
        /// Test that XSS attempts are blocked during user creation
        /// </summary>
        [Test]
        public async Task CreateUserAsync_ProtectsAgainstXSS()
        {
            // Arrange - XSS attempts
            var xssAttempts = new[]
            {
                ("<script>alert('XSS')</script>", "normal@email.com"),
                ("normaluser", "<script>document.cookie='stolen'</script>@evil.com"),
                ("<img src='x' onerror='alert(1)'>", "test@example.com"),
                ("user<svg onload='alert(1)'>", "test@domain.com"),
                ("javascript:alert('hack')", "email@test.com")
            };

            // Act & Assert
            foreach (var (maliciousUsername, maliciousEmail) in xssAttempts)
            {
                var result = await _userService.CreateUserAsync(maliciousUsername, maliciousEmail);
                
                // Should fail due to validation
                Assert.That(result.Success, Is.False, 
                    $"XSS attempt should be blocked: {maliciousUsername}, {maliciousEmail}");
            }
        }

        /// <summary>
        /// Test that legitimate users can be created successfully
        /// </summary>
        [Test]
        public async Task CreateUserAsync_AcceptsLegitimateUsers()
        {
            // Arrange
            var validUsers = new[]
            {
                ("john_doe", "john.doe@example.com"),
                ("alice123", "alice@company.org"),
                ("bob-wilson", "bob.wilson@university.edu")
            };

            // Act & Assert
            foreach (var (username, email) in validUsers)
            {
                var result = await _userService.CreateUserAsync(username, email);
                
                Assert.That(result.Success, Is.True, 
                    $"Valid user should be created: {username}, {email} - Error: {result.Message}");
                
                Assert.That(result.User, Is.Not.Null, "User object should be returned");
                Assert.That(result.User!.Username, Is.EqualTo(username), "Username should match");
                Assert.That(result.User!.Email, Is.EqualTo(email), "Email should match");
            }

            // Verify all users were created
            var userCount = await _context.Users.CountAsync();
            Assert.That(userCount, Is.EqualTo(validUsers.Length), "All valid users should be created");
        }

        /// <summary>
        /// Test user search functionality against injection attacks
        /// </summary>
        [Test]
        public async Task SearchUsersAsync_ProtectsAgainstSQLInjection()
        {
            // Arrange - Create a legitimate user first
            await _userService.CreateUserAsync("testuser", "test@example.com");

            var injectionAttempts = new[]
            {
                "'; DROP TABLE Users; --",
                "' OR '1'='1",
                "test'; DELETE FROM Users; --",
                "'; UNION SELECT * FROM Users; --"
            };

            // Act & Assert
            foreach (var maliciousSearch in injectionAttempts)
            {
                var users = await _userService.SearchUsersAsync(maliciousSearch);
                
                // Should return empty results and not crash
                Assert.That(users, Is.Not.Null, "Search should not return null");
                
                // Verify the original user still exists (wasn't deleted by injection)
                var originalUser = await _userService.GetUserByUsernameAsync("testuser");
                Assert.That(originalUser, Is.Not.Null, 
                    $"Original user should still exist after injection attempt: {maliciousSearch}");
            }
        }

        /// <summary>
        /// Test that user retrieval by username is secure
        /// </summary>
        [Test]
        public async Task GetUserByUsernameAsync_ProtectsAgainstInjection()
        {
            // Arrange - Create legitimate users
            await _userService.CreateUserAsync("admin", "admin@example.com");
            await _userService.CreateUserAsync("user1", "user1@example.com");

            var injectionAttempts = new[]
            {
                "admin'--",
                "' OR '1'='1",
                "admin'; DROP TABLE Users; --",
                "admin' UNION SELECT * FROM Users --"
            };

            // Act & Assert
            foreach (var maliciousUsername in injectionAttempts)
            {
                var user = await _userService.GetUserByUsernameAsync(maliciousUsername);
                
                // Should not find any user (injection should be blocked)
                Assert.That(user, Is.Null, 
                    $"Injection attempt should not return user: {maliciousUsername}");
            }

            // Verify legitimate search still works
            var adminUser = await _userService.GetUserByUsernameAsync("admin");
            Assert.That(adminUser, Is.Not.Null, "Legitimate user search should work");
            Assert.That(adminUser!.Username, Is.EqualTo("admin"), "Correct user should be returned");

            // Verify all users still exist
            var allUsers = await _context.Users.ToListAsync();
            Assert.That(allUsers.Count, Is.EqualTo(2), "All users should still exist after injection attempts");
        }

        /// <summary>
        /// Test duplicate user prevention
        /// </summary>
        [Test]
        public async Task CreateUserAsync_PreventsDuplicateUsers()
        {
            // Arrange
            const string username = "testuser";
            const string email = "test@example.com";

            // Act - Create first user
            var firstResult = await _userService.CreateUserAsync(username, email);
            Assert.That(firstResult.Success, Is.True, "First user should be created successfully");

            // Act - Try to create duplicate username
            var duplicateUsernameResult = await _userService.CreateUserAsync(username, "different@email.com");
            Assert.That(duplicateUsernameResult.Success, Is.False, "Duplicate username should be rejected");

            // Act - Try to create duplicate email
            var duplicateEmailResult = await _userService.CreateUserAsync("differentuser", email);
            Assert.That(duplicateEmailResult.Success, Is.False, "Duplicate email should be rejected");

            // Verify only one user exists
            var userCount = await _context.Users.CountAsync();
            Assert.That(userCount, Is.EqualTo(1), "Only one user should exist");
        }
    }
}
