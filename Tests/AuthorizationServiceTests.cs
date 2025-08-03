using NUnit.Framework;
using Microsoft.Extensions.Logging;
using SafeVault.Models;
using SafeVault.Services;

namespace SafeVault.Tests
{
    /// <summary>
    /// Comprehensive tests for authorization functionality
    /// </summary>
    [TestFixture]
    public class AuthorizationTests
    {
        private AuthorizationService _authorizationService = null!;
        private ILogger<AuthorizationService> _logger = null!;

        [SetUp]
        public void Setup()
        {
            var loggerFactory = LoggerFactory.Create(builder => builder.AddConsole());
            _logger = loggerFactory.CreateLogger<AuthorizationService>();
            _authorizationService = new AuthorizationService(_logger);
        }

        [Test]
        public void HasPermission_UserRole_CanViewProfile()
        {
            // Arrange
            var user = new User
            {
                UserID = 1,
                Username = "testuser",
                Email = "test@example.com",
                Role = "User",
                Status = "Active"
            };

            // Act
            var result = _authorizationService.HasPermission(user, AuthorizationService.Permission.ViewProfile);

            // Assert
            Assert.That(result, Is.True);
        }

        [Test]
        public void HasPermission_UserRole_CannotViewAllUsers()
        {
            // Arrange
            var user = new User
            {
                UserID = 1,
                Username = "testuser",
                Email = "test@example.com",
                Role = "User",
                Status = "Active"
            };

            // Act
            var result = _authorizationService.HasPermission(user, AuthorizationService.Permission.ViewAllUsers);

            // Assert
            Assert.That(result, Is.False);
        }

        [Test]
        public void HasPermission_AdminRole_CanViewAllUsers()
        {
            // Arrange
            var admin = new User
            {
                UserID = 1,
                Username = "admin",
                Email = "admin@example.com",
                Role = "Admin",
                Status = "Active"
            };

            // Act
            var result = _authorizationService.HasPermission(admin, AuthorizationService.Permission.ViewAllUsers);

            // Assert
            Assert.That(result, Is.True);
        }

        [Test]
        public void HasPermission_AdminRole_CanManageSystem()
        {
            // Arrange
            var admin = new User
            {
                UserID = 1,
                Username = "admin",
                Email = "admin@example.com",
                Role = "Admin",
                Status = "Active"
            };

            // Act
            var result = _authorizationService.HasPermission(admin, AuthorizationService.Permission.ManageSystem);

            // Assert
            Assert.That(result, Is.True);
        }

        [Test]
        public void HasPermission_ModeratorRole_CanModerateContent()
        {
            // Arrange
            var moderator = new User
            {
                UserID = 1,
                Username = "moderator",
                Email = "mod@example.com",
                Role = "Moderator",
                Status = "Active"
            };

            // Act
            var result = _authorizationService.HasPermission(moderator, AuthorizationService.Permission.ModerateContent);

            // Assert
            Assert.That(result, Is.True);
        }

        [Test]
        public void HasPermission_ModeratorRole_CannotManageSystem()
        {
            // Arrange
            var moderator = new User
            {
                UserID = 1,
                Username = "moderator",
                Email = "mod@example.com",
                Role = "Moderator",
                Status = "Active"
            };

            // Act
            var result = _authorizationService.HasPermission(moderator, AuthorizationService.Permission.ManageSystem);

            // Assert
            Assert.That(result, Is.False);
        }

        [Test]
        public void HasPermission_InactiveUser_ReturnsFalse()
        {
            // Arrange
            var inactiveUser = new User
            {
                UserID = 1,
                Username = "inactive",
                Email = "inactive@example.com",
                Role = "Admin",
                Status = "Locked"
            };

            // Act
            var result = _authorizationService.HasPermission(inactiveUser, AuthorizationService.Permission.ViewProfile);

            // Assert
            Assert.That(result, Is.False);
        }

        [Test]
        public void HasPermission_NullUser_ReturnsFalse()
        {
            // Act
            var result = _authorizationService.HasPermission(null!, AuthorizationService.Permission.ViewProfile);

            // Assert
            Assert.That(result, Is.False);
        }

        [Test]
        public void HasPermission_InvalidRole_ReturnsFalse()
        {
            // Arrange
            var userWithInvalidRole = new User
            {
                UserID = 1,
                Username = "invalidrole",
                Email = "invalid@example.com",
                Role = "InvalidRole",
                Status = "Active"
            };

            // Act
            var result = _authorizationService.HasPermission(userWithInvalidRole, AuthorizationService.Permission.ViewProfile);

            // Assert
            Assert.That(result, Is.False);
        }

        [Test]
        public void HasAnyPermission_UserWithMultiplePermissions_ReturnsTrue()
        {
            // Arrange
            var user = new User
            {
                UserID = 1,
                Username = "testuser",
                Email = "test@example.com",
                Role = "User",
                Status = "Active"
            };

            // Act
            var result = _authorizationService.HasAnyPermission(user, 
                AuthorizationService.Permission.ViewProfile, 
                AuthorizationService.Permission.ManageSystem);

            // Assert
            Assert.That(result, Is.True); // User has ViewProfile permission
        }

        [Test]
        public void HasAllPermissions_AdminWithAllPermissions_ReturnsTrue()
        {
            // Arrange
            var admin = new User
            {
                UserID = 1,
                Username = "admin",
                Email = "admin@example.com",
                Role = "Admin",
                Status = "Active"
            };

            // Act
            var result = _authorizationService.HasAllPermissions(admin, 
                AuthorizationService.Permission.ViewProfile, 
                AuthorizationService.Permission.ManageSystem);

            // Assert
            Assert.That(result, Is.True);
        }

        [Test]
        public void HasAllPermissions_UserWithoutAllPermissions_ReturnsFalse()
        {
            // Arrange
            var user = new User
            {
                UserID = 1,
                Username = "testuser",
                Email = "test@example.com",
                Role = "User",
                Status = "Active"
            };

            // Act
            var result = _authorizationService.HasAllPermissions(user, 
                AuthorizationService.Permission.ViewProfile, 
                AuthorizationService.Permission.ManageSystem);

            // Assert
            Assert.That(result, Is.False); // User doesn't have ManageSystem permission
        }

        [Test]
        public void IsAdmin_AdminUser_ReturnsTrue()
        {
            // Arrange
            var admin = new User
            {
                UserID = 1,
                Username = "admin",
                Email = "admin@example.com",
                Role = "Admin",
                Status = "Active"
            };

            // Act
            var result = _authorizationService.IsAdmin(admin);

            // Assert
            Assert.That(result, Is.True);
        }

        [Test]
        public void IsAdmin_RegularUser_ReturnsFalse()
        {
            // Arrange
            var user = new User
            {
                UserID = 1,
                Username = "testuser",
                Email = "test@example.com",
                Role = "User",
                Status = "Active"
            };

            // Act
            var result = _authorizationService.IsAdmin(user);

            // Assert
            Assert.That(result, Is.False);
        }

        [Test]
        public void IsModerator_ModeratorUser_ReturnsTrue()
        {
            // Arrange
            var moderator = new User
            {
                UserID = 1,
                Username = "moderator",
                Email = "mod@example.com",
                Role = "Moderator",
                Status = "Active"
            };

            // Act
            var result = _authorizationService.IsModerator(moderator);

            // Assert
            Assert.That(result, Is.True);
        }

        [Test]
        public void IsModerator_AdminUser_ReturnsTrue()
        {
            // Arrange
            var admin = new User
            {
                UserID = 1,
                Username = "admin",
                Email = "admin@example.com",
                Role = "Admin",
                Status = "Active"
            };

            // Act
            var result = _authorizationService.IsModerator(admin);

            // Assert
            Assert.That(result, Is.True); // Admins can also moderate
        }

        [Test]
        public void CanManageUser_UserManagingSelf_ReturnsTrue()
        {
            // Arrange
            var user = new User
            {
                UserID = 1,
                Username = "testuser",
                Email = "test@example.com",
                Role = "User",
                Status = "Active"
            };

            // Act
            var result = _authorizationService.CanManageUser(user, user);

            // Assert
            Assert.That(result, Is.True);
        }

        [Test]
        public void CanManageUser_AdminManagingUser_ReturnsTrue()
        {
            // Arrange
            var admin = new User
            {
                UserID = 1,
                Username = "admin",
                Email = "admin@example.com",
                Role = "Admin",
                Status = "Active"
            };

            var user = new User
            {
                UserID = 2,
                Username = "testuser",
                Email = "test@example.com",
                Role = "User",
                Status = "Active"
            };

            // Act
            var result = _authorizationService.CanManageUser(admin, user);

            // Assert
            Assert.That(result, Is.True);
        }

        [Test]
        public void CanManageUser_UserManagingOtherUser_ReturnsFalse()
        {
            // Arrange
            var user1 = new User
            {
                UserID = 1,
                Username = "user1",
                Email = "user1@example.com",
                Role = "User",
                Status = "Active"
            };

            var user2 = new User
            {
                UserID = 2,
                Username = "user2",
                Email = "user2@example.com",
                Role = "User",
                Status = "Active"
            };

            // Act
            var result = _authorizationService.CanManageUser(user1, user2);

            // Assert
            Assert.That(result, Is.False);
        }

        [Test]
        public void AuthorizeAction_ValidUserAndPermission_ReturnsAuthorized()
        {
            // Arrange
            var admin = new User
            {
                UserID = 1,
                Username = "admin",
                Email = "admin@example.com",
                Role = "Admin",
                Status = "Active"
            };

            // Act
            var result = _authorizationService.AuthorizeAction(admin, AuthorizationService.Permission.ManageSystem, "System management");

            // Assert
            Assert.That(result.IsAuthorized, Is.True);
            Assert.That(result.Message, Is.EqualTo("Authorization successful"));
        }

        [Test]
        public void AuthorizeAction_InsufficientPermissions_ReturnsUnauthorized()
        {
            // Arrange
            var user = new User
            {
                UserID = 1,
                Username = "testuser",
                Email = "test@example.com",
                Role = "User",
                Status = "Active"
            };

            // Act
            var result = _authorizationService.AuthorizeAction(user, AuthorizationService.Permission.ManageSystem, "System management");

            // Assert
            Assert.That(result.IsAuthorized, Is.False);
            Assert.That(result.Message, Does.Contain("Insufficient permissions"));
            Assert.That(result.RequiredRole, Is.EqualTo("Admin"));
        }

        [Test]
        public void GetUserPermissions_AdminUser_ReturnsAllPermissions()
        {
            // Arrange
            var admin = new User
            {
                UserID = 1,
                Username = "admin",
                Email = "admin@example.com",
                Role = "Admin",
                Status = "Active"
            };

            // Act
            var permissions = _authorizationService.GetUserPermissions(admin);

            // Assert
            Assert.That(permissions.Count, Is.GreaterThan(5));
            Assert.That(permissions, Contains.Item(AuthorizationService.Permission.ManageSystem));
            Assert.That(permissions, Contains.Item(AuthorizationService.Permission.ViewAllUsers));
        }

        [Test]
        public void GetUserPermissions_RegularUser_ReturnsLimitedPermissions()
        {
            // Arrange
            var user = new User
            {
                UserID = 1,
                Username = "testuser",
                Email = "test@example.com",
                Role = "User",
                Status = "Active"
            };

            // Act
            var permissions = _authorizationService.GetUserPermissions(user);

            // Assert
            Assert.That(permissions.Count, Is.LessThan(6));
            Assert.That(permissions, Contains.Item(AuthorizationService.Permission.ViewProfile));
            Assert.That(permissions, Does.Not.Contain(AuthorizationService.Permission.ManageSystem));
        }
    }
}
