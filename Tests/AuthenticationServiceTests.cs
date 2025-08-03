using NUnit.Framework;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging;
using SafeVault.Models;
using SafeVault.Services;

namespace SafeVault.Tests
{
    /// <summary>
    /// Comprehensive tests for authentication functionality
    /// </summary>
    [TestFixture]
    public class AuthenticationTests
    {
        private SafeVaultDbContext _context = null!;
        private AuthenticationService _authService = null!;
        private ILogger<AuthenticationService> _logger = null!;

        [SetUp]
        public void Setup()
        {
            // Create in-memory database for testing
            var options = new DbContextOptionsBuilder<SafeVaultDbContext>()
                .UseInMemoryDatabase(databaseName: Guid.NewGuid().ToString())
                .Options;

            _context = new SafeVaultDbContext(options);
            
            // Create logger
            var loggerFactory = LoggerFactory.Create(builder => builder.AddConsole());
            _logger = loggerFactory.CreateLogger<AuthenticationService>();
            
            _authService = new AuthenticationService(_context, _logger);
        }

        [TearDown]
        public void TearDown()
        {
            _context?.Dispose();
        }

        [Test]
        public void HashPassword_ValidPassword_ReturnsHashedPassword()
        {
            // Arrange
            var password = "TestPassword123!";

            // Act
            var hashedPassword = _authService.HashPassword(password);

            // Assert
            Assert.That(hashedPassword, Is.Not.Null);
            Assert.That(hashedPassword, Is.Not.EqualTo(password));
            Assert.That(hashedPassword.Length, Is.GreaterThan(50)); // BCrypt hashes are typically 60 chars
        }

        [Test]
        public void HashPassword_NullPassword_ThrowsArgumentException()
        {
            // Act & Assert
            Assert.Throws<ArgumentException>(() => _authService.HashPassword(null!));
            Assert.Throws<ArgumentException>(() => _authService.HashPassword(""));
            Assert.Throws<ArgumentException>(() => _authService.HashPassword("   "));
        }

        [Test]
        public void VerifyPassword_CorrectPassword_ReturnsTrue()
        {
            // Arrange
            var password = "TestPassword123!";
            var hash = _authService.HashPassword(password);

            // Act
            var result = _authService.VerifyPassword(password, hash);

            // Assert
            Assert.That(result, Is.True);
        }

        [Test]
        public void VerifyPassword_IncorrectPassword_ReturnsFalse()
        {
            // Arrange
            var password = "TestPassword123!";
            var wrongPassword = "WrongPassword123!";
            var hash = _authService.HashPassword(password);

            // Act
            var result = _authService.VerifyPassword(wrongPassword, hash);

            // Assert
            Assert.That(result, Is.False);
        }

        [Test]
        public async Task RegisterUserAsync_ValidInput_CreatesUser()
        {
            // Arrange
            var username = "testuser";
            var email = "test@example.com";
            var password = "TestPassword123!";

            // Act
            var result = await _authService.RegisterUserAsync(username, email, password);

            // Assert
            Assert.That(result.Success, Is.True);
            Assert.That(result.User, Is.Not.Null);
            Assert.That(result.User!.Username, Is.EqualTo(username));
            Assert.That(result.User.Email, Is.EqualTo(email));
            Assert.That(result.User.Role, Is.EqualTo("User"));
            Assert.That(result.User.Status, Is.EqualTo("Active"));
        }

        [Test]
        public async Task RegisterUserAsync_WeakPassword_ReturnsFalse()
        {
            // Arrange
            var username = "testuser";
            var email = "test@example.com";
            var weakPassword = "weak";

            // Act
            var result = await _authService.RegisterUserAsync(username, email, weakPassword);

            // Assert
            Assert.That(result.Success, Is.False);
            Assert.That(result.Message, Does.Contain("Password must be at least 8 characters"));
        }

        [Test]
        public async Task RegisterUserAsync_DuplicateUsername_ReturnsFalse()
        {
            // Arrange
            var username = "testuser";
            var email1 = "test1@example.com";
            var email2 = "test2@example.com";
            var password = "TestPassword123!";

            // Act
            await _authService.RegisterUserAsync(username, email1, password);
            var result = await _authService.RegisterUserAsync(username, email2, password);

            // Assert
            Assert.That(result.Success, Is.False);
            Assert.That(result.Message, Does.Contain("Username or email already exists"));
        }

        [Test]
        public async Task AuthenticateUserAsync_ValidCredentials_ReturnsSuccess()
        {
            // Arrange
            var username = "testuser";
            var email = "test@example.com";
            var password = "TestPassword123!";

            await _authService.RegisterUserAsync(username, email, password);

            // Act
            var result = await _authService.AuthenticateUserAsync(username, password);

            // Assert
            Assert.That(result.Success, Is.True);
            Assert.That(result.User, Is.Not.Null);
            Assert.That(result.User!.Username, Is.EqualTo(username));
        }

        [Test]
        public async Task AuthenticateUserAsync_InvalidCredentials_ReturnsFalse()
        {
            // Arrange
            var username = "testuser";
            var email = "test@example.com";
            var password = "TestPassword123!";
            var wrongPassword = "WrongPassword123!";

            await _authService.RegisterUserAsync(username, email, password);

            // Act
            var result = await _authService.AuthenticateUserAsync(username, wrongPassword);

            // Assert
            Assert.That(result.Success, Is.False);
            Assert.That(result.Message, Is.EqualTo("Invalid username or password"));
        }

        [Test]
        public async Task AuthenticateUserAsync_NonexistentUser_ReturnsFalse()
        {
            // Act
            var result = await _authService.AuthenticateUserAsync("nonexistent", "password");

            // Assert
            Assert.That(result.Success, Is.False);
            Assert.That(result.Message, Is.EqualTo("Invalid username or password"));
        }

        [Test]
        public async Task AuthenticateUserAsync_TooManyFailedAttempts_LocksAccount()
        {
            // Arrange
            var username = "testuser";
            var email = "test@example.com";
            var password = "TestPassword123!";
            var wrongPassword = "WrongPassword123!";

            await _authService.RegisterUserAsync(username, email, password);

            // Act - Attempt multiple failed logins
            for (int i = 0; i < 5; i++)
            {
                await _authService.AuthenticateUserAsync(username, wrongPassword);
            }

            // Try with correct password after account is locked
            var result = await _authService.AuthenticateUserAsync(username, password);

            // Assert
            Assert.That(result.Success, Is.False);
            Assert.That(result.Message, Does.Contain("Account is locked"));
        }

        [Test]
        public async Task AuthenticateUserAsync_SuccessfulLogin_UpdatesLastLoginTime()
        {
            // Arrange
            var username = "testuser";
            var email = "test@example.com";
            var password = "TestPassword123!";

            await _authService.RegisterUserAsync(username, email, password);

            // Act
            var result = await _authService.AuthenticateUserAsync(username, password);

            // Assert
            Assert.That(result.Success, Is.True);
            Assert.That(result.User!.LastLoginAt, Is.Not.Null);
            Assert.That(result.User.LastLoginAt, Is.GreaterThan(DateTime.UtcNow.AddMinutes(-1)));
        }

        [Test]
        public async Task UnlockUserAccountAsync_LockedAccount_UnlocksSuccessfully()
        {
            // Arrange
            var username = "testuser";
            var email = "test@example.com";
            var password = "TestPassword123!";
            var wrongPassword = "WrongPassword123!";

            await _authService.RegisterUserAsync(username, email, password);

            // Lock the account
            for (int i = 0; i < 5; i++)
            {
                await _authService.AuthenticateUserAsync(username, wrongPassword);
            }

            // Act
            var unlockResult = await _authService.UnlockUserAccountAsync(username);
            var loginResult = await _authService.AuthenticateUserAsync(username, password);

            // Assert
            Assert.That(unlockResult.Success, Is.True);
            Assert.That(loginResult.Success, Is.True);
        }
    }
}
