using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.InMemory;
using SafeVault.Services;
using SafeVault.Models;
using System.ComponentModel.DataAnnotations;

var builder = WebApplication.CreateBuilder(args);

// Configure Kestrel for both HTTP and HTTPS (commented out to allow --urls override)
// builder.WebHost.ConfigureKestrel(options =>
// {
//     options.ListenLocalhost(5000); // HTTP
//     options.ListenLocalhost(5001, listenOptions =>
//     {
//         listenOptions.UseHttps(); // HTTPS
//     });
// });

// Add services to the container
builder.Services.AddDbContext<SafeVaultDbContext>(options =>
    options.UseInMemoryDatabase("SafeVaultDb")); // Using in-memory DB for demo

builder.Services.AddScoped<UserService>();
builder.Services.AddScoped<AuthenticationService>();
builder.Services.AddScoped<AuthorizationService>();
builder.Services.AddSingleton<SessionService>();
builder.Services.AddScoped<InputValidationService>();
builder.Services.AddScoped<SecurityTestRunnerService>();
builder.Services.AddLogging();

// Add Razor Pages support
builder.Services.AddRazorPages(options =>
{
    // Configure Razor Pages options if needed
});

// Add Anti-forgery services
builder.Services.AddAntiforgery();

// Add CORS for security
builder.Services.AddCors(options =>
{
    options.AddDefaultPolicy(builder =>
    {
        builder.WithOrigins("https://localhost")
               .AllowAnyHeader()
               .AllowAnyMethod()
               .AllowCredentials();
    });
});

var app = builder.Build();

// Configure the HTTP request pipeline
if (app.Environment.IsDevelopment())
{
    app.UseDeveloperExceptionPage();
}
else
{
    app.UseExceptionHandler("/error");
    app.UseHsts();
    app.UseHttpsRedirection(); // Only redirect to HTTPS in production
}

app.UseStaticFiles();
app.UseCors();

// Add routing middleware (required for Razor Pages)
app.UseRouting();

// Add anti-forgery middleware
app.UseAntiforgery();

// Security headers middleware
app.Use(async (context, next) =>
{
    context.Response.Headers["X-Content-Type-Options"] = "nosniff";
    context.Response.Headers["X-Frame-Options"] = "DENY";
    context.Response.Headers["X-XSS-Protection"] = "1; mode=block";
    context.Response.Headers["Referrer-Policy"] = "strict-origin-when-cross-origin";
    context.Response.Headers["Content-Security-Policy"] = 
        "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; img-src 'self' data:;";
    
    await next();
});

// Create database and seed data
using (var scope = app.Services.CreateScope())
{
    var context = scope.ServiceProvider.GetRequiredService<SafeVaultDbContext>();
    context.Database.EnsureCreated();
    
    // Run authentication and authorization demonstration
    await RunAuthenticationDemo(scope);
}

// API Endpoints

// Authentication Endpoints
/// <summary>
/// User registration endpoint with password hashing
/// </summary>
app.MapPost("/auth/register", async (RegisterRequest request, AuthenticationService authService) =>
{
    try
    {
        var result = await authService.RegisterUserAsync(request.Username, request.Email, request.Password, request.Role ?? "User");
        
        if (result.Success)
        {
            return Results.Ok(new { 
                message = "User registered successfully", 
                userId = result.User?.UserID,
                role = result.User?.Role,
                success = true 
            });
        }
        else
        {
            return Results.BadRequest(new { 
                message = result.Message, 
                success = false 
            });
        }
    }
    catch (Exception ex)
    {
        app.Logger.LogError(ex, "Error during user registration");
        return Results.Problem("An error occurred during registration");
    }
});

/// <summary>
/// User login endpoint
/// </summary>
app.MapPost("/auth/login", async (LoginRequest request, AuthenticationService authService, SessionService sessionService) =>
{
    try
    {
        var result = await authService.AuthenticateUserAsync(request.Username, request.Password);
        
        if (result.Success && result.User != null)
        {
            var sessionId = sessionService.CreateSession(result.User, request.IpAddress ?? "", request.UserAgent ?? "");
            
            return Results.Ok(new { 
                message = "Login successful",
                sessionId = sessionId,
                user = new { 
                    id = result.User.UserID,
                    username = result.User.Username,
                    role = result.User.Role,
                    lastLogin = result.User.LastLoginAt
                },
                success = true 
            });
        }
        else
        {
            return Results.Unauthorized();
        }
    }
    catch (Exception ex)
    {
        app.Logger.LogError(ex, "Error during user login");
        return Results.Problem("An error occurred during login");
    }
});

/// <summary>
/// Logout endpoint
/// </summary>
app.MapPost("/auth/logout", (LogoutRequest request, SessionService sessionService) =>
{
    try
    {
        var removed = sessionService.RemoveSession(request.SessionId);
        return Results.Ok(new { 
            message = "Logged out successfully", 
            success = removed 
        });
    }
    catch (Exception ex)
    {
        app.Logger.LogError(ex, "Error during logout");
        return Results.Problem("An error occurred during logout");
    }
});

/// <summary>
/// Check permissions endpoint
/// </summary>
app.MapPost("/auth/check-permission", (PermissionRequest request, AuthorizationService authzService, SessionService sessionService) =>
{
    try
    {
        var user = sessionService.GetCurrentUser(request.SessionId);
        if (user == null)
        {
            return Results.Unauthorized();
        }

        if (!Enum.TryParse<AuthorizationService.Permission>(request.Permission, out var permission))
        {
            return Results.BadRequest(new { message = "Invalid permission" });
        }

        var hasPermission = authzService.HasPermission(user, permission);
        var authResult = authzService.AuthorizeAction(user, permission);

        return Results.Ok(new { 
            hasPermission = hasPermission,
            message = authResult.Message,
            requiredRole = authResult.RequiredRole,
            userRole = user.Role
        });
    }
    catch (Exception ex)
    {
        app.Logger.LogError(ex, "Error checking permissions");
        return Results.Problem("An error occurred while checking permissions");
    }
});

/// <summary>
/// Admin endpoint to unlock user accounts
/// </summary>
app.MapPost("/admin/unlock-user", async (UnlockUserRequest request, AuthenticationService authService, AuthorizationService authzService, SessionService sessionService) =>
{
    try
    {
        var currentUser = sessionService.GetCurrentUser(request.SessionId);
        if (currentUser == null)
        {
            return Results.Unauthorized();
        }

        if (!authzService.HasPermission(currentUser, AuthorizationService.Permission.UnlockAccounts))
        {
            return Results.Forbid();
        }

        var result = await authService.UnlockUserAccountAsync(request.Username);
        return Results.Ok(new { 
            message = result.Message, 
            success = result.Success 
        });
    }
    catch (Exception ex)
    {
        app.Logger.LogError(ex, "Error unlocking user account");
        return Results.Problem("An error occurred while unlocking the account");
    }
});

/// <summary>
/// Secure user registration endpoint with comprehensive validation
/// </summary>
app.MapPost("/submit", async (HttpContext context, UserService userService) =>
{
    try
    {
        var form = await context.Request.ReadFormAsync();
        var username = form["username"].ToString();
        var email = form["email"].ToString();

        // Validate required fields
        if (string.IsNullOrWhiteSpace(username))
        {
            return Results.BadRequest(new { 
                message = "Username is required", 
                success = false 
            });
        }

        if (string.IsNullOrWhiteSpace(email))
        {
            return Results.BadRequest(new { 
                message = "Email is required", 
                success = false 
            });
        }

        // Log the attempt (without sensitive data)
        app.Logger.LogInformation("User registration attempt for username length: {UsernameLength}", 
            username.Length);

        var result = await userService.CreateUserAsync(username, email);
        
        if (result.Success)
        {
            return Results.Ok(new { 
                message = "User registered successfully", 
                userId = result.User?.UserID,
                success = true 
            });
        }
        else
        {
            app.Logger.LogWarning("User registration failed: {Error}", result.Message);
            return Results.BadRequest(new { 
                message = result.Message, 
                success = false 
            });
        }
    }
    catch (Exception ex)
    {
        app.Logger.LogError(ex, "Error during user registration");
        return Results.Problem("An error occurred during registration");
    }
});

/// <summary>
/// Get user by ID endpoint (for testing)
/// </summary>
app.MapGet("/users/{id:int}", async (int id, UserService userService) =>
{
    try
    {
        var user = await userService.GetUserByIdAsync(id);
        if (user == null)
        {
            return Results.NotFound(new { message = "User not found" });
        }
        return Results.Ok(user);
    }
    catch (Exception ex)
    {
        app.Logger.LogError(ex, "Error retrieving user {UserId}", id);
        return Results.Problem("An error occurred while retrieving the user");
    }
});

/// <summary>
/// Search users endpoint (demonstrates secure search)
/// </summary>
app.MapGet("/users/search", async (string? q, UserService userService) =>
{
    try
    {
        if (string.IsNullOrEmpty(q))
        {
            return Results.BadRequest(new { message = "Search query is required" });
        }

        var users = await userService.SearchUsersAsync(q);
        return Results.Ok(users);
    }
    catch (Exception ex)
    {
        app.Logger.LogError(ex, "Error searching users");
        return Results.Problem("An error occurred while searching users");
    }
});

/// <summary>
/// Get all users with pagination (for testing)
/// </summary>
app.MapGet("/users", async (UserService userService, int page = 1, int pageSize = 10) =>
{
    try
    {
        var result = await userService.GetUsersAsync(page, pageSize);
        return Results.Ok(new { 
            users = result.Users, 
            totalCount = result.TotalCount,
            page = page,
            pageSize = pageSize
        });
    }
    catch (Exception ex)
    {
        app.Logger.LogError(ex, "Error retrieving users");
        return Results.Problem("An error occurred while retrieving users");
    }
});

/// <summary>
/// Validation test endpoint (for testing the validation service directly)
/// </summary>
app.MapPost("/validate", (ValidationRequest request) =>
{
    try
    {
        var result = InputValidationService.ValidateUserInput(request.Username, request.Email);
        
        return Results.Ok(new { 
            isValid = result.IsValid,
            errors = result.Errors,
            sanitizedUsername = InputValidationService.SanitizeInput(request.Username),
            sanitizedEmail = InputValidationService.SanitizeInput(request.Email)
        });
    }
    catch (Exception ex)
    {
        app.Logger.LogError(ex, "Error during validation test");
        return Results.Problem("An error occurred during validation");
    }
});

/// <summary>
/// Health check endpoint
/// </summary>
app.MapGet("/health", () => Results.Ok(new { 
    status = "healthy", 
    timestamp = DateTime.UtcNow 
}));

/// <summary>
/// Security test endpoint (demonstrates various attack attempts for educational purposes)
/// </summary>
app.MapPost("/security-test", (SecurityTestRequest request) =>
{
    try
    {
        var results = new Dictionary<string, object>();

        // Test SQL injection detection
        results["sql_injection_detected"] = !InputValidationService.IsInputSafe(request.TestInput);
        
        // Test XSS detection
        results["xss_detected"] = !InputValidationService.IsInputSafe(request.TestInput);
        
        // Show sanitized version
        results["sanitized_input"] = InputValidationService.SanitizeInput(request.TestInput);
        
        // Test username validation
        var usernameValidation = InputValidationService.ValidateUsername(request.TestInput);
        results["username_validation"] = new { 
            isValid = usernameValidation.IsValid, 
            error = usernameValidation.ErrorMessage 
        };

        return Results.Ok(results);
    }
    catch (Exception ex)
    {
        app.Logger.LogError(ex, "Error during security test");
        return Results.Problem("An error occurred during security test");
    }
});

// Error handling endpoint
app.MapGet("/error", () => Results.Problem("An unexpected error occurred"));

// Map Razor Pages
app.MapRazorPages();

app.Logger.LogInformation("SafeVault application started successfully");
app.Logger.LogInformation("Available endpoints:");
app.Logger.LogInformation("  Web Pages:");
app.Logger.LogInformation("    GET /security-tests - Security Test Dashboard (Enhanced with Activity 3 tests)");
app.Logger.LogInformation("    GET /vulnerable-demo - Activity 3: Vulnerable Demo Page");
app.Logger.LogInformation("    GET /secure-demo - Activity 3: Secure Demo Page (Fixed)");
app.Logger.LogInformation("  Authentication:");
app.Logger.LogInformation("    POST /auth/register - User registration with authentication");
app.Logger.LogInformation("    POST /auth/login - User login");
app.Logger.LogInformation("    POST /auth/logout - User logout");
app.Logger.LogInformation("    POST /auth/check-permission - Check user permissions");
app.Logger.LogInformation("    POST /admin/unlock-user - Admin: Unlock user account");
app.Logger.LogInformation("  Legacy endpoints:");
app.Logger.LogInformation("    POST /submit - User registration");
app.Logger.LogInformation("    GET /users/{{id}} - Get user by ID");
app.Logger.LogInformation("    GET /users/search?q=query - Search users");
app.Logger.LogInformation("    GET /users - Get all users (paginated)");
app.Logger.LogInformation("    POST /validate - Test input validation");
app.Logger.LogInformation("    POST /security-test - Test security measures");
app.Logger.LogInformation("    GET /health - Health check");

app.Run();

// Demo function to showcase authentication and authorization
static async Task RunAuthenticationDemo(IServiceScope scope)
{
    var authService = scope.ServiceProvider.GetRequiredService<AuthenticationService>();
    var authzService = scope.ServiceProvider.GetRequiredService<AuthorizationService>();
    var sessionService = scope.ServiceProvider.GetRequiredService<SessionService>();
    var logger = scope.ServiceProvider.GetRequiredService<ILogger<Program>>();

    logger.LogInformation("=== SafeVault Authentication & Authorization Demo ===");

    try
    {
        // Register demo users
        var users = new[]
        {
            ("demo_user", "user@demo.com", "UserPass123!", "User"),
            ("demo_mod", "mod@demo.com", "ModPass123!", "Moderator"),
            ("demo_admin", "admin@demo.com", "AdminPass123!", "Admin")
        };

        logger.LogInformation("1. Registering demo users...");
        foreach (var (username, email, password, role) in users)
        {
            var result = await authService.RegisterUserAsync(username, email, password, role);
            logger.LogInformation("   {Username} ({Role}): {Status}", 
                username, role, result.Success ? "SUCCESS" : "FAILED");
        }

        // Demonstrate authentication
        logger.LogInformation("2. Testing authentication...");
        var authResult = await authService.AuthenticateUserAsync("demo_admin", "AdminPass123!");
        if (authResult.Success && authResult.User != null)
        {
            logger.LogInformation("   Admin login: SUCCESS - Welcome {Username}!", authResult.User.Username);
            
            // Create session
            var sessionId = sessionService.CreateSession(authResult.User, "127.0.0.1", "Demo");
            logger.LogInformation("   Session created: {SessionId}", sessionId[..8] + "...");

            // Test permissions
            logger.LogInformation("3. Testing authorization...");
            var permissions = new[]
            {
                AuthorizationService.Permission.ViewProfile,
                AuthorizationService.Permission.ModerateContent,
                AuthorizationService.Permission.ManageSystem
            };

            foreach (var permission in permissions)
            {
                var hasPermission = authzService.HasPermission(authResult.User, permission);
                logger.LogInformation("   {Permission}: {Status}", 
                    permission, hasPermission ? "ALLOWED" : "DENIED");
            }
        }

        // Test failed login
        logger.LogInformation("4. Testing failed authentication...");
        var failedAuth = await authService.AuthenticateUserAsync("demo_user", "WrongPassword");
        logger.LogInformation("   Wrong password attempt: {Status}", 
            failedAuth.Success ? "SUCCESS" : "FAILED (Expected)");

        logger.LogInformation("=== Demo Complete - Application ready ===");
    }
    catch (Exception ex)
    {
        logger.LogError(ex, "Error during authentication demo");
    }
}

// DTO classes for API requests
public record ValidationRequest(string Username, string Email);
public record SecurityTestRequest(string TestInput);
public record RegisterRequest(string Username, string Email, string Password, string? Role = null);
public record LoginRequest(string Username, string Password, string? IpAddress = null, string? UserAgent = null);
public record LogoutRequest(string SessionId);
public record PermissionRequest(string SessionId, string Permission);
public record UnlockUserRequest(string SessionId, string Username);
