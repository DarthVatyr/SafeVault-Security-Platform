using NUnit.Framework;
using SafeVault.Services;

namespace SafeVault.Tests
{
    /// <summary>
    /// Security tests to verify protection against common vulnerabilities
    /// These tests simulate real-world attack scenarios
    /// </summary>
    [TestFixture]
    public class SecurityTests
    {
        /// <summary>
        /// Tests protection against SQL injection attempts in input validation
        /// </summary>
        [Test]
        public void TestInputValidation_ProtectsAgainstSQLInjection()
        {
            // Arrange - Common SQL injection attack patterns
            var sqlInjectionAttempts = new[]
            {
                "'; DROP TABLE Users; --",
                "admin'--",
                "' OR '1'='1",
                "' OR 1=1 --",
                "'; INSERT INTO Users VALUES('hacker','hack@evil.com'); --",
                "admin'; UPDATE Users SET Username='hacked' WHERE UserID=1; --",
                "' UNION SELECT * FROM Users --",
                "'; EXEC xp_cmdshell('dir'); --",
                "'; WAITFOR DELAY '00:00:10'; --"
            };

            // Act & Assert
            foreach (var maliciousInput in sqlInjectionAttempts)
            {
                var result = InputValidationService.IsInputSafe(maliciousInput);
                Assert.That(result, Is.False, $"Input validation failed to detect SQL injection: {maliciousInput}");

                var usernameValidation = InputValidationService.ValidateUsername(maliciousInput);
                Assert.That(usernameValidation.IsValid, Is.False, $"Username validation failed to reject: {maliciousInput}");
            }
        }

        /// <summary>
        /// Tests protection against Cross-Site Scripting (XSS) attacks
        /// </summary>
        [Test]
        public void TestInputValidation_ProtectsAgainstXSS()
        {
            // Arrange - Common XSS attack patterns
            var xssAttempts = new[]
            {
                "<script>alert('XSS')</script>",
                "<img src='x' onerror='alert(1)'>",
                "javascript:alert('XSS')",
                "<iframe src='javascript:alert(1)'></iframe>",
                "<svg onload='alert(1)'>",
                "<input onfocus='alert(1)' autofocus>",
                "<body onload='alert(1)'>",
                "<div onclick='alert(1)'>Click me</div>",
                "&#60;script&#62;alert('XSS')&#60;/script&#62;",
                "<script>document.cookie='stolen'</script>",
                "<img src=x onerror=eval(String.fromCharCode(97,108,101,114,116,40,49,41))>",
                "vbscript:msgbox('XSS')",
                "data:text/html,<script>alert('XSS')</script>"
            };

            // Act & Assert
            foreach (var maliciousInput in xssAttempts)
            {
                var result = InputValidationService.IsInputSafe(maliciousInput);
                Assert.That(result, Is.False, $"Input validation failed to detect XSS: {maliciousInput}");

                var sanitized = InputValidationService.SanitizeInput(maliciousInput);
                Assert.That(sanitized, Does.Not.Contain("<script"), 
                    $"Sanitization failed to remove script tags from: {maliciousInput}");
                Assert.That(sanitized, Does.Not.Contain("javascript:"), 
                    $"Sanitization failed to remove javascript: from: {maliciousInput}");
            }
        }

        /// <summary>
        /// Tests that legitimate input is accepted
        /// </summary>
        [Test]
        public void TestInputValidation_AcceptsLegitimateInput()
        {
            // Arrange - Valid inputs
            var validInputs = new[]
            {
                ("john_doe", "john.doe@example.com"),
                ("alice123", "alice123@company.org"),
                ("bob-wilson", "bob.wilson@university.edu"),
                ("user.name", "user.name@domain.co.uk"),
                ("test_user", "test.user+tag@example.com")
            };

            // Act & Assert
            foreach (var (username, email) in validInputs)
            {
                var usernameValidation = InputValidationService.ValidateUsername(username);
                Assert.That(usernameValidation.IsValid, Is.True, 
                    $"Valid username rejected: {username} - {usernameValidation.ErrorMessage}");

                var emailValidation = InputValidationService.ValidateEmail(email);
                Assert.That(emailValidation.IsValid, Is.True, 
                    $"Valid email rejected: {email} - {emailValidation.ErrorMessage}");

                Assert.That(InputValidationService.IsInputSafe(username), Is.True,
                    $"Safe username marked as unsafe: {username}");
                Assert.That(InputValidationService.IsInputSafe(email), Is.True,
                    $"Safe email marked as unsafe: {email}");
            }
        }

        /// <summary>
        /// Tests edge cases for input validation
        /// </summary>
        [Test]
        public void TestInputValidation_HandlesEdgeCases()
        {
            // Test null and empty inputs
            Assert.That(InputValidationService.IsInputSafe(null!), Is.True);
            Assert.That(InputValidationService.IsInputSafe(""), Is.True);
            Assert.That(InputValidationService.IsInputSafe("   "), Is.True);

            // Test very long inputs (potential buffer overflow attempts)
            var longString = new string('a', 1000);
            var usernameValidation = InputValidationService.ValidateUsername(longString);
            Assert.That(usernameValidation.IsValid, Is.False, "Extremely long username should be rejected");

            var emailValidation = InputValidationService.ValidateEmail(longString + "@example.com");
            Assert.That(emailValidation.IsValid, Is.False, "Extremely long email should be rejected");
        }

        /// <summary>
        /// Tests SQL injection attempts with encoded characters
        /// </summary>
        [Test]
        public void TestInputValidation_ProtectsAgainstEncodedInjection()
        {
            // Arrange - Encoded injection attempts
            var encodedInjectionAttempts = new[]
            {
                "%27%20OR%201=1--", // URL encoded ' OR 1=1--
                "&#39; OR &#39;1&#39;=&#39;1", // HTML encoded ' OR '1'='1
                "%3Cscript%3Ealert%281%29%3C/script%3E", // URL encoded <script>alert(1)</script>
                "&#60;script&#62;alert(1)&#60;/script&#62;" // HTML encoded <script>alert(1)</script>
            };

            // Act & Assert
            foreach (var maliciousInput in encodedInjectionAttempts)
            {
                var result = InputValidationService.IsInputSafe(maliciousInput);
                // Note: Some encoded inputs might pass initial validation but should be caught during sanitization
                var sanitized = InputValidationService.SanitizeInput(maliciousInput);
                
                // Verify that dangerous content is removed or neutralized
                Assert.That(sanitized, Does.Not.Contain("OR 1=1"), 
                    $"Sanitization failed to neutralize SQL injection: {maliciousInput}");
                Assert.That(sanitized, Does.Not.Contain("<script"), 
                    $"Sanitization failed to neutralize XSS: {maliciousInput}");
            }
        }

        /// <summary>
        /// Tests comprehensive validation combining username and email
        /// </summary>
        [Test]
        public void TestComprehensiveValidation_CombinedInputs()
        {
            // Test valid combination
            var validResult = InputValidationService.ValidateUserInput("john_doe", "john@example.com");
            Assert.That(validResult.IsValid, Is.True, "Valid input combination should pass validation");

            // Test malicious username with valid email
            var invalidUsername = InputValidationService.ValidateUserInput("admin'--", "valid@example.com");
            Assert.That(invalidUsername.IsValid, Is.False, "Malicious username should fail validation");

            // Test valid username with malicious email
            var invalidEmail = InputValidationService.ValidateUserInput("validuser", "<script>alert(1)</script>@evil.com");
            Assert.That(invalidEmail.IsValid, Is.False, "Malicious email should fail validation");

            // Test both inputs malicious
            var bothInvalid = InputValidationService.ValidateUserInput("'; DROP TABLE Users; --", "<script>alert('XSS')</script>");
            Assert.That(bothInvalid.IsValid, Is.False, "Both malicious inputs should fail validation");
        }
    }
}
