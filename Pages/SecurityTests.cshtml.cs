using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using SafeVault.Models;
using SafeVault.Services;

namespace SafeVault.Pages
{
    public class SecurityTestsModel : PageModel
    {
        private readonly SecurityTestRunnerService _testRunner;

        public SecurityTestsModel(SecurityTestRunnerService testRunner)
        {
            _testRunner = testRunner;
        }

        [BindProperty]
        public TestSummary? TestSummary { get; set; }

        [BindProperty]
        public List<TestResult> TestResults { get; set; } = new();

        [BindProperty]
        public bool TestsCompleted { get; set; } = false;

        [BindProperty]
        public bool TestsRunning { get; set; } = false;

        public void OnGet()
        {
            // Initial page load - show the "Run Tests" button
            TestsCompleted = false;
            TestsRunning = false;
            
            // Debug: Log the GET request
            Console.WriteLine($"[DEBUG] OnGet called - TestsCompleted: {TestsCompleted}");
        }

        public async Task<IActionResult> OnPostAsync()
        {
            var action = Request.Form["action"];
            
            if (action == "RunTests")
            {
                return await HandleRunTestsAsync();
            }
            else if (action == "ClearResults")
            {
                return HandleClearResults();
            }
            
            return Page();
        }

        private async Task<IActionResult> HandleRunTestsAsync()
        {
            // Debug: Log the POST request
            Console.WriteLine($"[DEBUG] HandleRunTestsAsync called - Starting test execution");
            
            TestsRunning = true;
            
            try
            {
                Console.WriteLine($"[DEBUG] About to call RunAllSecurityTestsAsync");
                var (summary, results) = await _testRunner.RunAllSecurityTestsAsync();
                Console.WriteLine($"[DEBUG] Tests completed - Results count: {results.Count}");
                
                TestSummary = summary;
                TestResults = results;
                TestsCompleted = true;
                TestsRunning = false;
            }
            catch (Exception ex)
            {
                Console.WriteLine($"[DEBUG] Exception in HandleRunTestsAsync: {ex.Message}");
                // Handle any errors during test execution
                TestSummary = new TestSummary
                {
                    TotalTests = 1,
                    PassedTests = 0,
                    FailedTests = 1,
                    ExecutionDate = DateTime.UtcNow
                };
                
                TestResults = new List<TestResult>
                {
                    new TestResult
                    {
                        TestName = "Test Execution",
                        Category = "System",
                        Passed = false,
                        ErrorMessage = $"Failed to execute tests: {ex.Message}"
                    }
                };
                
                TestsCompleted = true;
                TestsRunning = false;
            }

            return Page();
        }

        private IActionResult HandleClearResults()
        {
            TestsCompleted = false;
            TestsRunning = false;
            TestSummary = null;
            TestResults.Clear();
            
            return Page();
        }

        // Keep the old methods for now (but they won't be called)
        public async Task<IActionResult> OnPostRunTestsAsync()
        {
            // Debug: Log the POST request
            Console.WriteLine($"[DEBUG] OnPostRunTestsAsync called - Starting test execution");
            
            TestsRunning = true;
            
            try
            {
                Console.WriteLine($"[DEBUG] About to call RunAllSecurityTestsAsync");
                var (summary, results) = await _testRunner.RunAllSecurityTestsAsync();
                Console.WriteLine($"[DEBUG] Tests completed - Results count: {results.Count}");
                
                TestSummary = summary;
                TestResults = results;
                TestsCompleted = true;
                TestsRunning = false;
            }
            catch (Exception ex)
            {
                // Handle any errors during test execution
                TestSummary = new TestSummary
                {
                    TotalTests = 1,
                    PassedTests = 0,
                    FailedTests = 1,
                    ExecutionDate = DateTime.UtcNow
                };
                
                TestResults = new List<TestResult>
                {
                    new TestResult
                    {
                        TestName = "Test Execution",
                        Category = "System",
                        Passed = false,
                        ErrorMessage = $"Failed to execute tests: {ex.Message}"
                    }
                };
                
                TestsCompleted = true;
                TestsRunning = false;
            }

            return Page();
        }

        public IActionResult OnPostClearResults()
        {
            TestsCompleted = false;
            TestsRunning = false;
            TestSummary = null;
            TestResults.Clear();
            
            return Page();
        }

        // Helper methods for the Razor page
        public IEnumerable<TestResult> GetTestsByCategory(string category)
        {
            return TestResults.Where(t => t.Category == category).OrderBy(t => t.TestName);
        }

        public IEnumerable<string> GetCategories()
        {
            return TestResults.Select(t => t.Category).Distinct().OrderBy(c => c);
        }

        public int GetCategoryPassCount(string category)
        {
            return TestResults.Count(t => t.Category == category && t.Passed);
        }

        public int GetCategoryTotalCount(string category)
        {
            return TestResults.Count(t => t.Category == category);
        }
    }
}
