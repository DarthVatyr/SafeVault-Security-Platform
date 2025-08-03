using SafeVault.Models;

namespace SafeVault.Services
{
    /// <summary>
    /// Authorization service for role-based access control (RBAC)
    /// </summary>
    public class AuthorizationService
    {
        private readonly ILogger<AuthorizationService> _logger;

        public AuthorizationService(ILogger<AuthorizationService> logger)
        {
            _logger = logger;
        }

        /// <summary>
        /// Defines available permissions in the system
        /// </summary>
        public enum Permission
        {
            // User permissions
            ViewProfile,
            EditProfile,
            ViewVault,
            EditVault,

            // Admin permissions
            ViewAllUsers,
            EditAllUsers,
            DeleteUsers,
            ViewAuditLogs,
            ManageSystem,
            UnlockAccounts,

            // Moderator permissions
            ViewUserReports,
            ModerateContent
        }

        /// <summary>
        /// Defines role-permission mappings
        /// </summary>
        private static readonly Dictionary<string, List<Permission>> RolePermissions = new()
        {
            {
                "User", new List<Permission>
                {
                    Permission.ViewProfile,
                    Permission.EditProfile,
                    Permission.ViewVault,
                    Permission.EditVault
                }
            },
            {
                "Moderator", new List<Permission>
                {
                    Permission.ViewProfile,
                    Permission.EditProfile,
                    Permission.ViewVault,
                    Permission.EditVault,
                    Permission.ViewUserReports,
                    Permission.ModerateContent
                }
            },
            {
                "Admin", new List<Permission>
                {
                    Permission.ViewProfile,
                    Permission.EditProfile,
                    Permission.ViewVault,
                    Permission.EditVault,
                    Permission.ViewAllUsers,
                    Permission.EditAllUsers,
                    Permission.DeleteUsers,
                    Permission.ViewAuditLogs,
                    Permission.ManageSystem,
                    Permission.UnlockAccounts,
                    Permission.ViewUserReports,
                    Permission.ModerateContent
                }
            }
        };

        /// <summary>
        /// Checks if a user has a specific permission
        /// </summary>
        public bool HasPermission(User user, Permission permission)
        {
            if (user == null)
            {
                _logger.LogWarning("Permission check attempted with null user");
                return false;
            }

            if (user.Status != "Active")
            {
                _logger.LogWarning("Permission check attempted for inactive user: {Username}", user.Username);
                return false;
            }

            if (!RolePermissions.ContainsKey(user.Role))
            {
                _logger.LogWarning("Permission check attempted for user with invalid role: {Username}, {Role}", 
                    user.Username, user.Role);
                return false;
            }

            var hasPermission = RolePermissions[user.Role].Contains(permission);
            
            if (!hasPermission)
            {
                _logger.LogWarning("Permission denied for user {Username} with role {Role} for permission {Permission}", 
                    user.Username, user.Role, permission);
            }

            return hasPermission;
        }

        /// <summary>
        /// Checks if a user has any of the specified permissions
        /// </summary>
        public bool HasAnyPermission(User user, params Permission[] permissions)
        {
            return permissions.Any(permission => HasPermission(user, permission));
        }

        /// <summary>
        /// Checks if a user has all of the specified permissions
        /// </summary>
        public bool HasAllPermissions(User user, params Permission[] permissions)
        {
            return permissions.All(permission => HasPermission(user, permission));
        }

        /// <summary>
        /// Gets all permissions for a user's role
        /// </summary>
        public List<Permission> GetUserPermissions(User user)
        {
            if (user == null || user.Status != "Active" || !RolePermissions.ContainsKey(user.Role))
            {
                return new List<Permission>();
            }

            return RolePermissions[user.Role].ToList();
        }

        /// <summary>
        /// Checks if user can access admin features
        /// </summary>
        public bool IsAdmin(User user)
        {
            return HasPermission(user, Permission.ManageSystem);
        }

        /// <summary>
        /// Checks if user can moderate content
        /// </summary>
        public bool IsModerator(User user)
        {
            return HasAnyPermission(user, Permission.ModerateContent, Permission.ManageSystem);
        }

        /// <summary>
        /// Validates that a user can perform an action on another user
        /// </summary>
        public bool CanManageUser(User currentUser, User targetUser)
        {
            if (currentUser == null || targetUser == null)
                return false;

            // Users can always manage themselves (with appropriate permissions)
            if (currentUser.UserID == targetUser.UserID)
                return HasPermission(currentUser, Permission.EditProfile);

            // Only admins can manage other users
            if (!IsAdmin(currentUser))
                return false;

            // Admins cannot manage other admins (prevent privilege escalation)
            if (targetUser.Role == "Admin" && currentUser.Role != "Admin")
                return false;

            return HasPermission(currentUser, Permission.EditAllUsers);
        }

        /// <summary>
        /// Authorization result class
        /// </summary>
        public class AuthorizationResult
        {
            public bool IsAuthorized { get; set; }
            public string Message { get; set; } = string.Empty;
            public string RequiredRole { get; set; } = string.Empty;
            public List<Permission> RequiredPermissions { get; set; } = new();
        }

        /// <summary>
        /// Comprehensive authorization check with detailed result
        /// </summary>
        public AuthorizationResult AuthorizeAction(User user, Permission requiredPermission, string actionDescription = "")
        {
            var result = new AuthorizationResult
            {
                RequiredPermissions = new List<Permission> { requiredPermission }
            };

            if (user == null)
            {
                result.Message = "User authentication required";
                return result;
            }

            if (user.Status != "Active")
            {
                result.Message = "User account is not active";
                return result;
            }

            if (!HasPermission(user, requiredPermission))
            {
                result.Message = $"Insufficient permissions. Required: {requiredPermission}";
                result.RequiredRole = GetMinimumRoleForPermission(requiredPermission);
                return result;
            }

            result.IsAuthorized = true;
            result.Message = "Authorization successful";
            return result;
        }

        /// <summary>
        /// Gets the minimum role required for a permission
        /// </summary>
        private string GetMinimumRoleForPermission(Permission permission)
        {
            foreach (var rolePermission in RolePermissions.OrderBy(rp => GetRoleHierarchy(rp.Key)))
            {
                if (rolePermission.Value.Contains(permission))
                {
                    return rolePermission.Key;
                }
            }
            return "Admin";
        }

        /// <summary>
        /// Gets role hierarchy level (lower number = higher privilege)
        /// </summary>
        private int GetRoleHierarchy(string role)
        {
            return role switch
            {
                "Admin" => 1,
                "Moderator" => 2,
                "User" => 3,
                _ => 99
            };
        }
    }
}
