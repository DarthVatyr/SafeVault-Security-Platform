namespace SafeVault.Models
{
    /// <summary>
    /// Model to represent individual test results for dashboard display
    /// </summary>
    public class TestResult
    {
        public string TestName { get; set; } = string.Empty;
        public string Category { get; set; } = string.Empty;
        public bool Passed { get; set; }
        public string ErrorMessage { get; set; } = string.Empty;
        public TimeSpan ExecutionTime { get; set; }
        public string Description { get; set; } = string.Empty;
    }

    /// <summary>
    /// Summary statistics for test execution
    /// </summary>
    public class TestSummary
    {
        public int TotalTests { get; set; }
        public int PassedTests { get; set; }
        public int FailedTests { get; set; }
        public TimeSpan TotalExecutionTime { get; set; }
        public DateTime ExecutionDate { get; set; }
        
        public double PassRate => TotalTests > 0 ? (double)PassedTests / TotalTests * 100 : 0;
    }
}
