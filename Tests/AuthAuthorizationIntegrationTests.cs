using NUnit.Framework;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging;
using SafeVault.Models;
using SafeVault.Services;

namespace SafeVault.Tests
{
    /// <summary>
    /// Integration tests for authentication and authorization working together
    /// </summary>
    [TestFixture]
    public class AuthenticationAuthorizationIntegrationTests
    {
        private SafeVaultDbContext _context = null!;
        private AuthenticationService _authService = null!;
        private AuthorizationService _authorizationService = null!;
        private SessionService _sessionService = null!;

        [SetUp]
        public void Setup()
        {
            // Create in-memory database for testing
            var options = new DbContextOptionsBuilder<SafeVaultDbContext>()
                .UseInMemoryDatabase(databaseName: Guid.NewGuid().ToString())
                .Options;

            _context = new SafeVaultDbContext(options);
            
            // Create loggers
            var loggerFactory = LoggerFactory.Create(builder => builder.AddConsole());
            var authLogger = loggerFactory.CreateLogger<AuthenticationService>();
            var authzLogger = loggerFactory.CreateLogger<AuthorizationService>();
            var sessionLogger = loggerFactory.CreateLogger<SessionService>();
            
            _authService = new AuthenticationService(_context, authLogger);
            _authorizationService = new AuthorizationService(authzLogger);
            _sessionService = new SessionService(sessionLogger);
        }

        [TearDown]
        public void TearDown()
        {
            _context?.Dispose();
        }

        [Test]
        public async Task CompleteUserJourney_RegisterLoginAndAuthorize_WorksCorrectly()
        {
            // Step 1: Register a regular user
            var username = "testuser";
            var email = "test@example.com";
            var password = "TestPassword123!";

            var registerResult = await _authService.RegisterUserAsync(username, email, password);
            Assert.That(registerResult.Success, Is.True);
            Assert.That(registerResult.User!.Role, Is.EqualTo("User"));

            // Step 2: Authenticate the user
            var authResult = await _authService.AuthenticateUserAsync(username, password);
            Assert.That(authResult.Success, Is.True);
            Assert.That(authResult.User, Is.Not.Null);

            // Step 3: Create a session
            var sessionId = _sessionService.CreateSession(authResult.User!, "192.168.1.1", "TestBrowser");
            Assert.That(sessionId, Is.Not.Null);

            // Step 4: Test user permissions
            var canViewProfile = _authorizationService.HasPermission(authResult.User!, AuthorizationService.Permission.ViewProfile);
            var canManageSystem = _authorizationService.HasPermission(authResult.User!, AuthorizationService.Permission.ManageSystem);

            Assert.That(canViewProfile, Is.True);
            Assert.That(canManageSystem, Is.False);

            // Step 5: Verify session works
            var currentUser = _sessionService.GetCurrentUser(sessionId);
            Assert.That(currentUser, Is.Not.Null);
            Assert.That(currentUser!.Username, Is.EqualTo(username));
        }

        [Test]
        public async Task AdminUserJourney_RegisterAdminAndTestPermissions_WorksCorrectly()
        {
            // Step 1: Register an admin user
            var adminUsername = "admin";
            var adminEmail = "admin@example.com";
            var adminPassword = "AdminPassword123!";

            var registerResult = await _authService.RegisterUserAsync(adminUsername, adminEmail, adminPassword, "Admin");
            Assert.That(registerResult.Success, Is.True);
            Assert.That(registerResult.User!.Role, Is.EqualTo("Admin"));

            // Step 2: Authenticate the admin
            var authResult = await _authService.AuthenticateUserAsync(adminUsername, adminPassword);
            Assert.That(authResult.Success, Is.True);

            // Step 3: Test admin permissions
            var canViewProfile = _authorizationService.HasPermission(authResult.User!, AuthorizationService.Permission.ViewProfile);
            var canManageSystem = _authorizationService.HasPermission(authResult.User!, AuthorizationService.Permission.ManageSystem);
            var canViewAllUsers = _authorizationService.HasPermission(authResult.User!, AuthorizationService.Permission.ViewAllUsers);

            Assert.That(canViewProfile, Is.True);
            Assert.That(canManageSystem, Is.True);
            Assert.That(canViewAllUsers, Is.True);

            // Step 4: Verify admin can manage users
            var regularUser = new User { UserID = 2, Username = "user", Role = "User", Status = "Active" };
            var canManageUser = _authorizationService.CanManageUser(authResult.User!, regularUser);

            Assert.That(canManageUser, Is.True);
        }

        [Test]
        public async Task AccountLockingFlow_MultipleFailedAttempts_LocksAndUnlocks()
        {
            // Step 1: Register a user
            var username = "locktest";
            var email = "locktest@example.com";
            var password = "TestPassword123!";
            var wrongPassword = "WrongPassword123!";

            await _authService.RegisterUserAsync(username, email, password);

            // Step 2: Attempt multiple failed logins
            for (int i = 0; i < 5; i++)
            {
                await _authService.AuthenticateUserAsync(username, wrongPassword);
            }

            // Step 3: Verify account is locked
            var lockedResult = await _authService.AuthenticateUserAsync(username, password);
            Assert.That(lockedResult.Success, Is.False);
            Assert.That(lockedResult.Message, Does.Contain("locked"));

            // Step 4: Unlock the account (admin action)
            var unlockResult = await _authService.UnlockUserAccountAsync(username);
            Assert.That(unlockResult.Success, Is.True);

            // Step 5: Verify user can login again
            var successResult = await _authService.AuthenticateUserAsync(username, password);
            Assert.That(successResult.Success, Is.True);
        }

        [Test]
        public async Task RoleBasedAccessControl_DifferentRoles_HaveDifferentPermissions()
        {
            // Create users with different roles
            var userResult = await _authService.RegisterUserAsync("user", "user@example.com", "Password123!", "User");
            var modResult = await _authService.RegisterUserAsync("mod", "mod@example.com", "Password123!", "Moderator");
            var adminResult = await _authService.RegisterUserAsync("admin", "admin@example.com", "Password123!", "Admin");

            Assert.That(userResult.Success, Is.True);
            Assert.That(modResult.Success, Is.True);
            Assert.That(adminResult.Success, Is.True);

            var user = userResult.User!;
            var moderator = modResult.User!;
            var admin = adminResult.User!;

            // Test view profile permission (all should have it)
            Assert.That(_authorizationService.HasPermission(user, AuthorizationService.Permission.ViewProfile), Is.True);
            Assert.That(_authorizationService.HasPermission(moderator, AuthorizationService.Permission.ViewProfile), Is.True);
            Assert.That(_authorizationService.HasPermission(admin, AuthorizationService.Permission.ViewProfile), Is.True);

            // Test moderate content permission (mod and admin should have it)
            Assert.That(_authorizationService.HasPermission(user, AuthorizationService.Permission.ModerateContent), Is.False);
            Assert.That(_authorizationService.HasPermission(moderator, AuthorizationService.Permission.ModerateContent), Is.True);
            Assert.That(_authorizationService.HasPermission(admin, AuthorizationService.Permission.ModerateContent), Is.True);

            // Test system management permission (only admin should have it)
            Assert.That(_authorizationService.HasPermission(user, AuthorizationService.Permission.ManageSystem), Is.False);
            Assert.That(_authorizationService.HasPermission(moderator, AuthorizationService.Permission.ManageSystem), Is.False);
            Assert.That(_authorizationService.HasPermission(admin, AuthorizationService.Permission.ManageSystem), Is.True);
        }

        [Test]
        public async Task SessionManagement_MultipleUsersAndSessions_WorksCorrectly()
        {
            // Register multiple users
            var user1Result = await _authService.RegisterUserAsync("user1", "user1@example.com", "Password123!");
            var user2Result = await _authService.RegisterUserAsync("user2", "user2@example.com", "Password123!");

            var user1 = user1Result.User!;
            var user2 = user2Result.User!;

            // Create multiple sessions
            var session1 = _sessionService.CreateSession(user1, "192.168.1.1", "Browser1");
            var session2 = _sessionService.CreateSession(user1, "192.168.1.2", "Browser2");
            var session3 = _sessionService.CreateSession(user2, "192.168.1.3", "Browser3");

            // Verify session counts
            var user1Sessions = _sessionService.GetUserSessions(user1.UserID);
            var user2Sessions = _sessionService.GetUserSessions(user2.UserID);
            var totalSessions = _sessionService.GetActiveSessionCount();

            Assert.That(user1Sessions.Count, Is.EqualTo(2));
            Assert.That(user2Sessions.Count, Is.EqualTo(1));
            Assert.That(totalSessions, Is.EqualTo(3));

            // Test session validation
            Assert.That(_sessionService.ValidateUserSession(session1, user1.UserID), Is.True);
            Assert.That(_sessionService.ValidateUserSession(session1, user2.UserID), Is.False);

            // Remove all sessions for user1
            _sessionService.RemoveAllUserSessions(user1.UserID);
            
            var remainingSessions = _sessionService.GetActiveSessionCount();
            Assert.That(remainingSessions, Is.EqualTo(1));
        }

        [Test]
        public async Task AuthorizationResult_DetailedAuthorizationCheck_ProvidesCorrectFeedback()
        {
            // Register a regular user
            var userResult = await _authService.RegisterUserAsync("user", "user@example.com", "Password123!");
            var user = userResult.User!;

            // Test successful authorization
            var successResult = _authorizationService.AuthorizeAction(user, AuthorizationService.Permission.ViewProfile, "View user profile");
            Assert.That(successResult.IsAuthorized, Is.True);
            Assert.That(successResult.Message, Is.EqualTo("Authorization successful"));

            // Test failed authorization
            var failResult = _authorizationService.AuthorizeAction(user, AuthorizationService.Permission.ManageSystem, "Manage system");
            Assert.That(failResult.IsAuthorized, Is.False);
            Assert.That(failResult.Message, Does.Contain("Insufficient permissions"));
            Assert.That(failResult.RequiredRole, Is.EqualTo("Admin"));
        }
    }
}
