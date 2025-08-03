#!/usr/bin/env pwsh
# SafeVault Authentication & Authorization API Test Script

$baseUrl = "http://localhost:5000"

Write-Host "=== SafeVault Authentication & Authorization API Tests ===" -ForegroundColor Green
Write-Host ""

# Test 1: Register a new user
Write-Host "1. Testing User Registration" -ForegroundColor Yellow
$registerData = @{
    Username = "testuser123"
    Email = "testuser@example.com"
    Password = "TestPassword123!"
    Role = "User"
} | ConvertTo-Json

try {
    $response = Invoke-RestMethod -Uri "$baseUrl/auth/register" -Method POST -Body $registerData -ContentType "application/json"
    Write-Host "   Registration Result: SUCCESS" -ForegroundColor Green
    Write-Host "   User ID: $($response.userId)" -ForegroundColor White
    Write-Host "   Role: $($response.role)" -ForegroundColor White
} catch {
    Write-Host "   Registration Result: FAILED - $($_.Exception.Message)" -ForegroundColor Red
}

Write-Host ""

# Test 2: Login with the registered user
Write-Host "2. Testing User Login" -ForegroundColor Yellow
$loginData = @{
    Username = "testuser123"
    Password = "TestPassword123!"
    IpAddress = "127.0.0.1"
    UserAgent = "PowerShell Test Script"
} | ConvertTo-Json

try {
    $loginResponse = Invoke-RestMethod -Uri "$baseUrl/auth/login" -Method POST -Body $loginData -ContentType "application/json"
    Write-Host "   Login Result: SUCCESS" -ForegroundColor Green
    Write-Host "   Session ID: $($loginResponse.sessionId.Substring(0,8))..." -ForegroundColor White
    Write-Host "   Username: $($loginResponse.user.username)" -ForegroundColor White
    Write-Host "   Role: $($loginResponse.user.role)" -ForegroundColor White
    
    $sessionId = $loginResponse.sessionId
} catch {
    Write-Host "   Login Result: FAILED - $($_.Exception.Message)" -ForegroundColor Red
    $sessionId = $null
}

Write-Host ""

# Test 3: Check permissions
if ($sessionId) {
    Write-Host "3. Testing Permission Checks" -ForegroundColor Yellow
    
    $permissions = @("ViewProfile", "ModerateContent", "ManageSystem")
    
    foreach ($permission in $permissions) {
        $permissionData = @{
            SessionId = $sessionId
            Permission = $permission
        } | ConvertTo-Json
        
        try {
            $permResponse = Invoke-RestMethod -Uri "$baseUrl/auth/check-permission" -Method POST -Body $permissionData -ContentType "application/json"
            $status = if ($permResponse.hasPermission) { "ALLOWED" } else { "DENIED" }
            $color = if ($permResponse.hasPermission) { "Green" } else { "Red" }
            Write-Host "   $permission`: $status" -ForegroundColor $color
        } catch {
            Write-Host "   $permission`: ERROR - $($_.Exception.Message)" -ForegroundColor Red
        }
    }
} else {
    Write-Host "3. Skipping permission checks (no session)" -ForegroundColor Gray
}

Write-Host ""

# Test 4: Login with admin account (from demo)
Write-Host "4. Testing Admin Login" -ForegroundColor Yellow
$adminLoginData = @{
    Username = "demo_admin"
    Password = "AdminPass123!"
    IpAddress = "127.0.0.1"
    UserAgent = "PowerShell Test Script"
} | ConvertTo-Json

try {
    $adminLoginResponse = Invoke-RestMethod -Uri "$baseUrl/auth/login" -Method POST -Body $adminLoginData -ContentType "application/json"
    Write-Host "   Admin Login Result: SUCCESS" -ForegroundColor Green
    Write-Host "   Admin Session ID: $($adminLoginResponse.sessionId.Substring(0,8))..." -ForegroundColor White
    Write-Host "   Admin Role: $($adminLoginResponse.user.role)" -ForegroundColor White
    
    $adminSessionId = $adminLoginResponse.sessionId
} catch {
    Write-Host "   Admin Login Result: FAILED - $($_.Exception.Message)" -ForegroundColor Red
    $adminSessionId = $null
}

Write-Host ""

# Test 5: Test admin permissions
if ($adminSessionId) {
    Write-Host "5. Testing Admin Permissions" -ForegroundColor Yellow
    
    $permissions = @("ViewProfile", "ModerateContent", "ManageSystem", "UnlockAccounts")
    
    foreach ($permission in $permissions) {
        $permissionData = @{
            SessionId = $adminSessionId
            Permission = $permission
        } | ConvertTo-Json
        
        try {
            $permResponse = Invoke-RestMethod -Uri "$baseUrl/auth/check-permission" -Method POST -Body $permissionData -ContentType "application/json"
            $status = if ($permResponse.hasPermission) { "ALLOWED" } else { "DENIED" }
            $color = if ($permResponse.hasPermission) { "Green" } else { "Red" }
            Write-Host "   $permission`: $status" -ForegroundColor $color
        } catch {
            Write-Host "   $permission`: ERROR - $($_.Exception.Message)" -ForegroundColor Red
        }
    }
} else {
    Write-Host "5. Skipping admin permission checks (no admin session)" -ForegroundColor Gray
}

Write-Host ""

# Test 6: Test failed login (for account locking demonstration)
Write-Host "6. Testing Failed Login Attempts" -ForegroundColor Yellow
$failedLoginData = @{
    Username = "testuser123"
    Password = "WrongPassword123!"
} | ConvertTo-Json

for ($i = 1; $i -le 3; $i++) {
    try {
        $response = Invoke-RestMethod -Uri "$baseUrl/auth/login" -Method POST -Body $failedLoginData -ContentType "application/json"
        Write-Host "   Attempt $i`: Unexpected SUCCESS" -ForegroundColor Red
    } catch {
        Write-Host "   Attempt $i`: FAILED (Expected)" -ForegroundColor Green
    }
}

Write-Host ""

# Test 7: Logout
Write-Host "7. Testing Logout" -ForegroundColor Yellow
if ($sessionId) {
    $logoutData = @{
        SessionId = $sessionId
    } | ConvertTo-Json
    
    try {
        $response = Invoke-RestMethod -Uri "$baseUrl/auth/logout" -Method POST -Body $logoutData -ContentType "application/json"
        Write-Host "   Logout Result: SUCCESS" -ForegroundColor Green
    } catch {
        Write-Host "   Logout Result: FAILED - $($_.Exception.Message)" -ForegroundColor Red
    }
} else {
    Write-Host "   No session to logout" -ForegroundColor Gray
}

Write-Host ""
Write-Host "=== API Tests Complete ===" -ForegroundColor Green
Write-Host ""
Write-Host "You can also test the legacy endpoints:" -ForegroundColor Cyan
Write-Host "  GET  $baseUrl/health" -ForegroundColor White
Write-Host "  GET  $baseUrl/users" -ForegroundColor White
Write-Host "  POST $baseUrl/validate" -ForegroundColor White
