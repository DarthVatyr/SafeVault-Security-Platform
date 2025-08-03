using SafeVault.Models;
using System.Collections.Concurrent;

namespace SafeVault.Services
{
    /// <summary>
    /// Simple session management service for tracking authenticated users
    /// In a production environment, consider using more robust session management
    /// </summary>
    public class SessionService
    {
        private readonly ILogger<SessionService> _logger;
        private readonly ConcurrentDictionary<string, SessionInfo> _activeSessions;

        public SessionService(ILogger<SessionService> logger)
        {
            _logger = logger;
            _activeSessions = new ConcurrentDictionary<string, SessionInfo>();
        }

        /// <summary>
        /// Session information
        /// </summary>
        public class SessionInfo
        {
            public string SessionId { get; set; } = string.Empty;
            public User User { get; set; } = null!;
            public DateTime LoginTime { get; set; }
            public DateTime LastActivity { get; set; }
            public string IpAddress { get; set; } = string.Empty;
            public string UserAgent { get; set; } = string.Empty;
        }

        /// <summary>
        /// Creates a new session for a user
        /// </summary>
        public string CreateSession(User user, string ipAddress = "", string userAgent = "")
        {
            var sessionId = Guid.NewGuid().ToString();
            var sessionInfo = new SessionInfo
            {
                SessionId = sessionId,
                User = user,
                LoginTime = DateTime.UtcNow,
                LastActivity = DateTime.UtcNow,
                IpAddress = ipAddress,
                UserAgent = userAgent
            };

            _activeSessions[sessionId] = sessionInfo;
            _logger.LogInformation("Session created for user {Username} with session ID {SessionId}", 
                user.Username, sessionId);

            return sessionId;
        }

        /// <summary>
        /// Gets session information by session ID
        /// </summary>
        public SessionInfo? GetSession(string sessionId)
        {
            if (string.IsNullOrWhiteSpace(sessionId))
                return null;

            if (_activeSessions.TryGetValue(sessionId, out var session))
            {
                // Check if session is expired (24 hours)
                if (DateTime.UtcNow - session.LastActivity > TimeSpan.FromHours(24))
                {
                    RemoveSession(sessionId);
                    return null;
                }

                // Update last activity
                session.LastActivity = DateTime.UtcNow;
                return session;
            }

            return null;
        }

        /// <summary>
        /// Gets the current user from a session
        /// </summary>
        public User? GetCurrentUser(string sessionId)
        {
            var session = GetSession(sessionId);
            return session?.User;
        }

        /// <summary>
        /// Removes a session (logout)
        /// </summary>
        public bool RemoveSession(string sessionId)
        {
            if (string.IsNullOrWhiteSpace(sessionId))
                return false;

            var removed = _activeSessions.TryRemove(sessionId, out var session);
            if (removed && session != null)
            {
                _logger.LogInformation("Session removed for user {Username} with session ID {SessionId}", 
                    session.User.Username, sessionId);
            }

            return removed;
        }

        /// <summary>
        /// Gets all sessions for a specific user
        /// </summary>
        public List<SessionInfo> GetUserSessions(int userId)
        {
            return _activeSessions.Values
                .Where(s => s.User.UserID == userId)
                .ToList();
        }

        /// <summary>
        /// Removes all sessions for a specific user
        /// </summary>
        public void RemoveAllUserSessions(int userId)
        {
            var userSessions = GetUserSessions(userId);
            foreach (var session in userSessions)
            {
                RemoveSession(session.SessionId);
            }
        }

        /// <summary>
        /// Gets count of active sessions
        /// </summary>
        public int GetActiveSessionCount()
        {
            CleanupExpiredSessions();
            return _activeSessions.Count;
        }

        /// <summary>
        /// Cleans up expired sessions
        /// </summary>
        public void CleanupExpiredSessions()
        {
            var expiredSessions = _activeSessions.Values
                .Where(s => DateTime.UtcNow - s.LastActivity > TimeSpan.FromHours(24))
                .Select(s => s.SessionId)
                .ToList();

            foreach (var sessionId in expiredSessions)
            {
                RemoveSession(sessionId);
            }

            if (expiredSessions.Any())
            {
                _logger.LogInformation("Cleaned up {Count} expired sessions", expiredSessions.Count);
            }
        }

        /// <summary>
        /// Validates that a session belongs to a specific user
        /// </summary>
        public bool ValidateUserSession(string sessionId, int userId)
        {
            var session = GetSession(sessionId);
            return session?.User.UserID == userId;
        }
    }
}
