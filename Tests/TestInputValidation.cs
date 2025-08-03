using NUnit.Framework;
using SafeVault.Services;

namespace SafeVault.Tests
{
    /// <summary>
    /// Test class matching the original activity template structure
    /// </summary>
    [TestFixture]
    public class TestInputValidation
    {
        /// <summary>
        /// Test for SQL Injection protection as specified in the activity
        /// </summary>
        [Test]
        public void TestForSQLInjection()
        {
            // Arrange - SQL injection test cases
            var sqlInjectionPayloads = new[]
            {
                "'; DROP TABLE Users; --",
                "admin'--",
                "' OR '1'='1",
                "' OR 1=1 --",
                "admin'; DELETE FROM Users; --",
                "'; INSERT INTO Users VALUES('hacker', 'hack@evil.com'); --",
                "' UNION SELECT password FROM Users WHERE username='admin'--",
                "'; EXEC xp_cmdshell('format c:'); --"
            };

            // Act & Assert - Test each SQL injection attempt
            foreach (var payload in sqlInjectionPayloads)
            {
                // Test username validation
                var usernameResult = InputValidationService.ValidateUsername(payload);
                Assert.That(usernameResult.IsValid, Is.False, 
                    $"SQL injection should be blocked in username: {payload}");

                // Test general input safety
                var isSafe = InputValidationService.IsInputSafe(payload);
                Assert.That(isSafe, Is.False, 
                    $"SQL injection should be detected as unsafe: {payload}");

                // Test sanitization removes dangerous content
                var sanitized = InputValidationService.SanitizeInput(payload);
                Assert.That(sanitized, Does.Not.Contain("DROP TABLE"), 
                    $"Sanitization should remove DROP TABLE: {payload}");
                Assert.That(sanitized, Does.Not.Contain("DELETE FROM"), 
                    $"Sanitization should remove DELETE FROM: {payload}");
                Assert.That(sanitized, Does.Not.Contain("INSERT INTO"), 
                    $"Sanitization should remove INSERT INTO: {payload}");
            }

            // Verify legitimate input still passes
            var validUsername = "john_doe";
            var validResult = InputValidationService.ValidateUsername(validUsername);
            Assert.That(validResult.IsValid, Is.True, "Valid username should pass validation");
        }

        /// <summary>
        /// Test for XSS (Cross-Site Scripting) protection as specified in the activity
        /// </summary>
        [Test]
        public void TestForXSS()
        {
            // Arrange - XSS attack test cases
            var xssPayloads = new[]
            {
                "<script>alert('XSS')</script>",
                "<img src='x' onerror='alert(\"XSS\")'>",
                "javascript:alert('XSS')",
                "<iframe src='javascript:alert(1)'></iframe>",
                "<svg onload='alert(1)'>",
                "<body onload='alert(\"XSS\")'>",
                "<input onfocus='alert(1)' autofocus>",
                "<div onclick='alert(1)'>Click me</div>",
                "&#60;script&#62;alert('XSS')&#60;/script&#62;",
                "<script>document.cookie='stolen'</script>",
                "vbscript:msgbox('XSS')",
                "data:text/html,<script>alert('XSS')</script>",
                "<object data='javascript:alert(1)'>",
                "<embed src='javascript:alert(1)'>",
                "<link rel='stylesheet' href='javascript:alert(1)'>"
            };

            // Act & Assert - Test each XSS attempt
            foreach (var payload in xssPayloads)
            {
                // Test general input safety
                var isSafe = InputValidationService.IsInputSafe(payload);
                Assert.That(isSafe, Is.False, 
                    $"XSS attack should be detected as unsafe: {payload}");

                // Test sanitization removes dangerous content
                var sanitized = InputValidationService.SanitizeInput(payload);
                Assert.That(sanitized, Does.Not.Contain("<script"), 
                    $"Sanitization should remove script tags: {payload}");
                Assert.That(sanitized, Does.Not.Contain("javascript:"), 
                    $"Sanitization should remove javascript: protocol: {payload}");
                Assert.That(sanitized, Does.Not.Contain("vbscript:"), 
                    $"Sanitization should remove vbscript: protocol: {payload}");
                Assert.That(sanitized, Does.Not.Contain("onload="), 
                    $"Sanitization should remove onload events: {payload}");
                Assert.That(sanitized, Does.Not.Contain("onerror="), 
                    $"Sanitization should remove onerror events: {payload}");

                // Test email validation specifically
                if (payload.Contains("@"))
                {
                    var emailResult = InputValidationService.ValidateEmail(payload);
                    Assert.That(emailResult.IsValid, Is.False, 
                        $"XSS in email should be rejected: {payload}");
                }
            }

            // Verify legitimate input still passes
            var validEmail = "user@example.com";
            var validResult = InputValidationService.ValidateEmail(validEmail);
            Assert.That(validResult.IsValid, Is.True, "Valid email should pass validation");

            var validInput = "Hello World";
            var validSafe = InputValidationService.IsInputSafe(validInput);
            Assert.That(validSafe, Is.True, "Safe input should be marked as safe");
        }

        /// <summary>
        /// Additional test to verify both SQL injection and XSS protection work together
        /// </summary>
        [Test]
        public void TestCombinedSQLInjectionAndXSS()
        {
            // Arrange - Combined attack payloads
            var combinedPayloads = new[]
            {
                "'; DROP TABLE Users; --<script>alert('XSS')</script>",
                "<script>alert('XSS')</script>'; DELETE FROM Users; --",
                "admin'--<img src='x' onerror='alert(1)'>",
                "<iframe src='javascript:alert(1)'></iframe>' OR '1'='1"
            };

            // Act & Assert
            foreach (var payload in combinedPayloads)
            {
                var isSafe = InputValidationService.IsInputSafe(payload);
                Assert.That(isSafe, Is.False, 
                    $"Combined attack should be detected: {payload}");

                var sanitized = InputValidationService.SanitizeInput(payload);
                
                // Should remove both SQL and XSS elements
                Assert.That(sanitized, Does.Not.Contain("DROP TABLE"), 
                    $"Should remove SQL injection: {payload}");
                Assert.That(sanitized, Does.Not.Contain("<script"), 
                    $"Should remove XSS script tags: {payload}");
                Assert.That(sanitized, Does.Not.Contain("javascript:"), 
                    $"Should remove javascript protocol: {payload}");
            }
        }

        /// <summary>
        /// Test to verify input length limits (protection against buffer overflow attempts)
        /// </summary>
        [Test]
        public void TestInputLengthLimits()
        {
            // Arrange - Create very long inputs
            var longUsername = new string('a', 200); // Exceeds 100 char limit
            var longEmail = new string('b', 200) + "@example.com"; // Exceeds 100 char limit

            // Act & Assert
            var usernameResult = InputValidationService.ValidateUsername(longUsername);
            Assert.That(usernameResult.IsValid, Is.False, "Overly long username should be rejected");

            var emailResult = InputValidationService.ValidateEmail(longEmail);
            Assert.That(emailResult.IsValid, Is.False, "Overly long email should be rejected");
        }
    }
}
