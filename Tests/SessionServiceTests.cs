using NUnit.Framework;
using Microsoft.Extensions.Logging;
using SafeVault.Models;
using SafeVault.Services;

namespace SafeVault.Tests
{
    /// <summary>
    /// Tests for session management functionality
    /// </summary>
    [TestFixture]
    public class SessionServiceTests
    {
        private SessionService _sessionService = null!;
        private ILogger<SessionService> _logger = null!;

        [SetUp]
        public void Setup()
        {
            var loggerFactory = LoggerFactory.Create(builder => builder.AddConsole());
            _logger = loggerFactory.CreateLogger<SessionService>();
            _sessionService = new SessionService(_logger);
        }

        [Test]
        public void CreateSession_ValidUser_ReturnsSessionId()
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
            var sessionId = _sessionService.CreateSession(user, "192.168.1.1", "TestUserAgent");

            // Assert
            Assert.That(sessionId, Is.Not.Null);
            Assert.That(sessionId, Is.Not.Empty);
            Assert.That(Guid.TryParse(sessionId, out _), Is.True);
        }

        [Test]
        public void GetSession_ValidSessionId_ReturnsSessionInfo()
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

            var sessionId = _sessionService.CreateSession(user, "192.168.1.1", "TestUserAgent");

            // Act
            var session = _sessionService.GetSession(sessionId);

            // Assert
            Assert.That(session, Is.Not.Null);
            Assert.That(session!.User.UserID, Is.EqualTo(user.UserID));
            Assert.That(session.IpAddress, Is.EqualTo("192.168.1.1"));
            Assert.That(session.UserAgent, Is.EqualTo("TestUserAgent"));
        }

        [Test]
        public void GetSession_InvalidSessionId_ReturnsNull()
        {
            // Act
            var session = _sessionService.GetSession("invalid-session-id");

            // Assert
            Assert.That(session, Is.Null);
        }

        [Test]
        public void GetSession_EmptySessionId_ReturnsNull()
        {
            // Act
            var session1 = _sessionService.GetSession("");
            var session2 = _sessionService.GetSession(null!);
            var session3 = _sessionService.GetSession("   ");

            // Assert
            Assert.That(session1, Is.Null);
            Assert.That(session2, Is.Null);
            Assert.That(session3, Is.Null);
        }

        [Test]
        public void GetCurrentUser_ValidSession_ReturnsUser()
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

            var sessionId = _sessionService.CreateSession(user);

            // Act
            var currentUser = _sessionService.GetCurrentUser(sessionId);

            // Assert
            Assert.That(currentUser, Is.Not.Null);
            Assert.That(currentUser!.UserID, Is.EqualTo(user.UserID));
            Assert.That(currentUser.Username, Is.EqualTo(user.Username));
        }

        [Test]
        public void GetCurrentUser_InvalidSession_ReturnsNull()
        {
            // Act
            var currentUser = _sessionService.GetCurrentUser("invalid-session-id");

            // Assert
            Assert.That(currentUser, Is.Null);
        }

        [Test]
        public void RemoveSession_ValidSession_ReturnsTrue()
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

            var sessionId = _sessionService.CreateSession(user);

            // Act
            var removed = _sessionService.RemoveSession(sessionId);
            var session = _sessionService.GetSession(sessionId);

            // Assert
            Assert.That(removed, Is.True);
            Assert.That(session, Is.Null);
        }

        [Test]
        public void RemoveSession_InvalidSession_ReturnsFalse()
        {
            // Act
            var removed = _sessionService.RemoveSession("invalid-session-id");

            // Assert
            Assert.That(removed, Is.False);
        }

        [Test]
        public void GetUserSessions_MultipleSessionsForUser_ReturnsAllSessions()
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

            var sessionId1 = _sessionService.CreateSession(user, "192.168.1.1", "Browser1");
            var sessionId2 = _sessionService.CreateSession(user, "192.168.1.2", "Browser2");

            // Act
            var userSessions = _sessionService.GetUserSessions(user.UserID);

            // Assert
            Assert.That(userSessions.Count, Is.EqualTo(2));
            Assert.That(userSessions.All(s => s.User.UserID == user.UserID), Is.True);
        }

        [Test]
        public void RemoveAllUserSessions_MultipleSessionsForUser_RemovesAllSessions()
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

            var sessionId1 = _sessionService.CreateSession(user, "192.168.1.1", "Browser1");
            var sessionId2 = _sessionService.CreateSession(user, "192.168.1.2", "Browser2");

            // Act
            _sessionService.RemoveAllUserSessions(user.UserID);
            var userSessions = _sessionService.GetUserSessions(user.UserID);

            // Assert
            Assert.That(userSessions.Count, Is.EqualTo(0));
        }

        [Test]
        public void GetActiveSessionCount_MultipleSessions_ReturnsCorrectCount()
        {
            // Arrange
            var user1 = new User { UserID = 1, Username = "user1", Email = "user1@example.com", Role = "User", Status = "Active" };
            var user2 = new User { UserID = 2, Username = "user2", Email = "user2@example.com", Role = "User", Status = "Active" };

            _sessionService.CreateSession(user1);
            _sessionService.CreateSession(user2);

            // Act
            var count = _sessionService.GetActiveSessionCount();

            // Assert
            Assert.That(count, Is.EqualTo(2));
        }

        [Test]
        public void ValidateUserSession_ValidSessionAndUser_ReturnsTrue()
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

            var sessionId = _sessionService.CreateSession(user);

            // Act
            var isValid = _sessionService.ValidateUserSession(sessionId, user.UserID);

            // Assert
            Assert.That(isValid, Is.True);
        }

        [Test]
        public void ValidateUserSession_WrongUser_ReturnsFalse()
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

            var sessionId = _sessionService.CreateSession(user);

            // Act
            var isValid = _sessionService.ValidateUserSession(sessionId, 999); // Wrong user ID

            // Assert
            Assert.That(isValid, Is.False);
        }

        [Test]
        public void CleanupExpiredSessions_OldSessions_RemovesExpiredSessions()
        {
            // This test would require manipulating time or dependency injection for DateTime
            // For now, we'll test the basic functionality
            
            // Arrange
            var user = new User
            {
                UserID = 1,
                Username = "testuser",
                Email = "test@example.com",
                Role = "User",
                Status = "Active"
            };

            _sessionService.CreateSession(user);

            // Act
            _sessionService.CleanupExpiredSessions(); // Should not remove recent sessions

            // Assert
            var count = _sessionService.GetActiveSessionCount();
            Assert.That(count, Is.EqualTo(1));
        }
    }
}
