# SafeVault - Complete Security Platform with Interactive Dashboard

## 🎯 Project Overview

SafeVault is a comprehensive secure web application demonstrating enterprise-grade security practices with an **interactive security test dashboard**. This project implements **Activities 1, 2, and 3** - the complete security development lifecycle from secure coding to vulnerability detection and hardening, all with a professional web interface for testing and demonstrating security features.

## 🛡️ Complete Security Features

### 🎨 Interactive Security Dashboard (ENHANCED!)
- **Professional web interface** for running security tests
- **Real-time test execution** with visual feedback
- **52 comprehensive security tests** across 10 categories
- **100% success rate** with all tests passing
- **Color-coded results** with pass/fail indicators
- **Execution timing** and detailed error reporting
- **Pure C#/Razor implementation** (no JavaScript required)
- **Mobile-responsive design** with Bootstrap 5.3

### 🚨 Activity 3: Security Debugging and Hardening (NEW!)
- **Vulnerability demonstration pages** showing common attack vectors
- **Secure implementation examples** with proper protections
- **Enhanced security testing** with 21 additional tests
- **Attack pattern detection** with 50+ security patterns
- **Educational security platform** for learning and demonstration

### 1. Input Validation and Sanitization (Activity 1)
- **Multi-layer validation**: Both client-side and server-side validation
- **SQL injection protection**: Detects and blocks common SQL injection patterns
- **XSS protection**: Prevents script injection and malicious HTML
- **Pattern recognition**: Advanced regex patterns to detect encoded attacks
- **Length validation**: Prevents buffer overflow attempts

### 2. Authentication System (Activity 2)
- **Secure password hashing** with BCrypt (cost factor 12)
- **User registration** with strong password requirements
- **User login** with credential verification
- **Account locking** after 5 failed login attempts
- **Account unlocking** (admin function)
- **Password strength validation**
- **Security logging** for all authentication events

### 3. Authorization System (RBAC)
- **Role-based access control** with User, Moderator, and Admin roles
- **Granular permissions** system with 10+ specific permissions
- **Role hierarchy** with privilege inheritance
- **Permission checking** with detailed feedback
- **User management** authorization controls
- **Admin dashboard** protection

### 4. Session Management
- **Secure session creation** with GUID-based session IDs
- **Session validation** and expiration (24 hours)
- **Multi-session support** per user
- **Session cleanup** functionality
- **IP address and user agent** tracking
- **Secure session termination**

### 5. Database Security
- **Parameterized queries**: All database operations use Entity Framework Core
- **No raw SQL concatenation**: Eliminates SQL injection vulnerabilities
- **Input sanitization**: Additional layer of protection
- **Database constraints**: Unique indexes and proper relationships
- **Audit logging**: Comprehensive security event logging

## 📁 Enhanced Project Structure

```
SafeVault/
├── Models/
│   ├── User.cs                      # Enhanced user model with auth support
│   └── TestResult.cs                # Security test result models
├── Services/
│   ├── AuthenticationService.cs     # Secure authentication with BCrypt
│   ├── AuthorizationService.cs      # Role-based access control (RBAC)
│   ├── SessionService.cs            # Session management
│   ├── InputValidationService.cs    # Comprehensive input validation (Enhanced)
│   ├── SafeVaultDbContext.cs        # Secure database context
│   ├── UserService.cs               # Secure user operations
│   └── SecurityTestRunnerService.cs # Interactive security test execution (52 tests)
├── Pages/
│   ├── Index.cshtml(.cs)            # Professional landing page
│   ├── SecurityTests.cshtml(.cs)    # Interactive security dashboard
│   ├── VulnerableDemo.cshtml(.cs)   # Activity 3: Vulnerability demonstration
│   ├── SecureDemo.cshtml(.cs)       # Activity 3: Secure implementation examples
│   ├── Shared/
│   │   ├── _Layout.cshtml            # Bootstrap 5.3 layout
│   │   └── _ViewStart.cshtml         # View configuration
├── Tests/
│   ├── AuthenticationServiceTests.cs    # Authentication testing (27 tests)
│   ├── AuthorizationServiceTests.cs     # Authorization testing (25 tests)
│   ├── SessionServiceTests.cs           # Session management tests (14 tests)
│   ├── AuthAuthorizationIntegrationTests.cs # Integration tests (6 tests)
│   ├── SecurityTests.cs                 # General security tests
│   ├── UserServiceSecurityTests.cs      # Database security tests
│   └── TestInputValidation.cs           # Input validation tests
├── wwwroot/
│   └── webform.html                 # Secure HTML form
├── Program.cs                       # Integrated application with all features
├── appsettings.json                 # Configuration with HTTPS settings
├── test-auth-api.ps1               # PowerShell API testing script
├── database.sql                    # Secure database schema
├── ACTIVITY_SUMMARY.md             # Complete summary of all three activities
└── README.md                       # This comprehensive documentation
```

## 🚀 How to Run the Application

### Prerequisites
- .NET 9.0 SDK
- Visual Studio Code or Visual Studio

### Steps

1. **Restore packages**:
   ```bash
   dotnet restore
   ```

2. **Run comprehensive tests** (72 tests total):
   ```bash
   dotnet test --verbosity normal
   ```

3. **Start the application**:
   ```bash
   dotnet run
   ```

4. **Access the application**:
   - **Landing Page**: `https://localhost:5001` (professional homepage)
   - **Security Dashboard**: `https://localhost:5001/security-tests` ⭐ **ENHANCED!**
   - **Vulnerable Demo**: `https://localhost:5001/vulnerable-demo` ⭐ **NEW! (Activity 3)**
   - **Secure Demo**: `https://localhost:5001/secure-demo` ⭐ **NEW! (Activity 3)**
   - **HTTP Alternative**: `http://localhost:5000` (development)
   - **Legacy Web Form**: `http://localhost:5000/webform.html`
   - **API endpoints**: See comprehensive list below

## 🎨 Interactive Security Dashboard Features

### 🚀 **Professional Interface**
- **Modern Bootstrap 5.3 design** with gradient backgrounds
- **Responsive layout** that works on all devices
- **Font Awesome icons** for visual enhancement
- **Color-coded results** (green = pass, red = fail)
- **Professional typography** and spacing

### ⚡ **Real-Time Test Execution**
- **52 comprehensive tests** across 10 security categories:
  - Input Validation (13 tests)
  - SQL Injection Prevention (2 tests)
  - XSS Prevention (2 tests)
  - User Model Security (4 tests)
  - Authentication (4 tests)
  - Authorization (3 tests)
  - Session Management (3 tests)
  - **Vulnerability Detection (9 tests)** ⭐ **NEW!**
  - **Security Hardening (7 tests)** ⭐ **NEW!**
  - **CSRF Protection (5 tests)** ⭐ **NEW!**

### 📊 **Detailed Results Display**
- **Test summary** with pass/fail counts and success rate
- **Execution timing** for performance monitoring
- **Category organization** with individual test details
- **Error messages** for failed tests with detailed diagnostics
- **Progress indicators** and status badges

### 🎯 **Interactive Controls**
- **Run Security Tests** button for test execution
- **Clear Results** to reset the dashboard
- **Run Again** for repeated testing
- **Pure server-side rendering** (no JavaScript dependencies)

## 🔧 Complete API Endpoints

### 🔐 Authentication Endpoints (Activity 2)
- **POST** `/auth/register` - User registration with password hashing
- **POST** `/auth/login` - User login with session creation
- **POST** `/auth/logout` - Session termination
- **POST** `/auth/check-permission` - Permission verification
- **POST** `/admin/unlock-user` - Admin function to unlock accounts

### 🎨 Interactive Dashboard (ENHANCED!)
- **GET** `/security-tests` - Interactive security test dashboard (52 tests)
- **POST** `/security-tests` - Execute security tests with web interface
- **GET** `/` - Professional landing page with navigation
- **GET** `/vulnerable-demo` - Activity 3: Vulnerability demonstration page ⭐ **NEW!**
- **GET** `/secure-demo` - Activity 3: Secure implementation examples ⭐ **NEW!**

### 👥 User Management (Activity 1)
- **POST** `/submit` - Legacy user registration
- **GET** `/users/{id}` - Get user by ID
- **GET** `/users/search?q={query}` - Search users securely
- **GET** `/users?page={page}&pageSize={size}` - Get all users with pagination

### 🛡️ Security Testing
- **POST** `/validate` - Test input validation
- **POST** `/security-test` - Test security measures
- **GET** `/health` - Health check

## 🧪 Interactive Security Test Results

**Total Tests: 52** | **Status: ✅ All Pass (100%)** | **Dashboard: Enhanced**

### 🎯 **Test Categories in Dashboard:**

#### Input Validation (13 tests)
✅ SQL Injection blocking: `'; DROP TABLE Users; --`, `' OR '1'='1`, etc.  
✅ XSS attack prevention: `<script>alert('XSS')</script>`, encoded attacks  
✅ Valid input acceptance: Proper usernames and safe content  

#### SQL Injection Prevention (2 tests)
✅ Database query protection with parameterized queries  
✅ Search function safety against injection attempts  

#### XSS Prevention (2 tests)
✅ HTML encoding protection against script injection  
✅ JavaScript protocol blocking for malicious URLs  

#### **Vulnerability Detection (9 tests)** ⭐ **NEW!**
✅ XSS Script Tag Detection  
✅ XSS JavaScript URL Detection  
✅ XSS Event Handler Detection  
✅ SQL Injection Boolean Attack Detection  
✅ SQL Injection Union Attack Detection  
✅ SQL Injection Comment Attack Detection  
✅ Path Traversal Attack Detection  
✅ Windows Path Traversal Detection  
✅ Command Injection Detection  

#### **Security Hardening (7 tests)** ⭐ **NEW!**
✅ Username Validation Enforcement  
✅ Email Validation Enforcement  
✅ HTML Tag Sanitization  
✅ JavaScript Event Sanitization  
✅ SQL Keyword Sanitization  
✅ Parameterized Query Protection  
✅ Generic Error Messages  

#### **CSRF Protection (5 tests)** ⭐ **NEW!**
✅ Anti-Forgery Token Required  
✅ Form Method Security  
✅ Session Management Security  
✅ Secure Headers Validation  
✅ Input Length Restrictions  

#### User Model Security (4 tests)
✅ Username validation with security rules  
✅ Email validation preventing malicious input  
✅ Password strength validation enforcement  
✅ Role validation with proper constraints  

#### Authentication (4 tests)
✅ User registration with unique email handling  
✅ Password hashing verification (BCrypt)  
✅ Login validation end-to-end  
✅ Invalid login protection  

#### Authorization (3 tests)
✅ Permission system validation  
✅ Role hierarchy enforcement  
✅ Authorization action verification  

#### Session Management (3 tests)
✅ Session creation and ID generation  
✅ Session validation and retrieval  
✅ Invalid session rejection  

### 📊 **Dashboard Performance Metrics:**
- **Average execution time**: <800ms for all 52 tests
- **Success rate**: 100% (52/52 tests passing)
- **Real-time feedback**: Instant results display
- **Error handling**: Detailed diagnostics for any failures
- **Enhanced coverage**: 68% more tests than baseline (52 vs 31)  

## 🔐 Advanced Security Implementation

### Authentication Flow
```csharp
// Secure user registration
var result = await authService.RegisterUserAsync(username, email, password, role);

// BCrypt password hashing (cost factor 12)
var hashedPassword = BCrypt.Net.BCrypt.HashPassword(password, 12);

// Secure login with account locking
var authResult = await authService.AuthenticateUserAsync(username, password);
```

### Authorization System
```csharp
// Role-based permission checking
var hasPermission = authzService.HasPermission(user, Permission.ManageSystem);

// Detailed authorization results
var authResult = authzService.AuthorizeAction(user, Permission.ViewAllUsers);
```

### Session Security
```csharp
// Secure session creation
var sessionId = sessionService.CreateSession(user, ipAddress, userAgent);

// Session validation with expiration
var currentUser = sessionService.GetCurrentUser(sessionId);
```

## 📊 Complete Security Coverage

### 🎨 **Interactive Dashboard Testing:**
| Category | Tests | Pass Rate | Execution Time | Visual Feedback |
|----------|-------|-----------|----------------|-----------------|
| **Input Validation** | 13 | 100% | <50ms | ✅ Green indicators |
| **SQL Injection Prevention** | 2 | 100% | <200ms | ✅ Protection verified |
| **XSS Prevention** | 2 | 100% | <10ms | ✅ Attacks blocked |
| **User Model Security** | 4 | 100% | <5ms | ✅ Validation passed |
| **Authentication** | 4 | 100% | <400ms | ✅ Auth working |
| **Authorization** | 3 | 100% | <5ms | ✅ RBAC verified |
| **Session Management** | 3 | 100% | <5ms | ✅ Sessions secure |
| **Vulnerability Detection** | 9 | 100% | <10ms | ✅ **NEW! Activity 3** |
| **Security Hardening** | 7 | 100% | <20ms | ✅ **NEW! Activity 3** |
| **CSRF Protection** | 5 | 100% | <15ms | ✅ **NEW! Activity 3** |
| **Dashboard Total** | **52** | **100%** | **<800ms** | **🎯 All Green** |

### 🔧 **Unit Testing Coverage:**
| Security Domain | Unit Tests | Features | Status |
|----------------|------------|----------|--------|
| **Authentication** | 27 | BCrypt hashing, login, account locking | ✅ Complete |
| **Authorization** | 25 | RBAC, permissions, role hierarchy | ✅ Complete |
| **Session Management** | 14 | Secure sessions, multi-device support | ✅ Complete |
| **Integration** | 6 | End-to-end security workflows | ✅ Complete |
| **Unit Test Total** | **72** | **Enterprise Security Suite** | **✅ All Pass** |

### 🏆 **Combined Coverage:**
- **Dashboard Tests**: 52 (interactive web testing)
- **Unit Tests**: 72 (comprehensive automated testing)  
- **Total Security Coverage**: **124 tests** across all security domains
- **Overall Pass Rate**: **100%** (124/124 tests passing)

## � User Roles and Permissions

### 👤 User Role
- View own profile
- Edit own profile  
- View own vault
- Edit own vault

### 🛡️ Moderator Role
- All User permissions, plus:
- View user reports
- Moderate content

### 👑 Admin Role  
- All Moderator permissions, plus:
- View all users
- Edit all users
- Delete users
- View audit logs
- Manage system
- Unlock accounts

## 🚀 Quick Start Guide

### 🎯 **For Security Demonstration:**
1. **Start the application**: `dotnet run`
2. **Open security dashboard**: `https://localhost:5001/security-tests`
3. **Click "Run Security Tests"** - See all 52 tests execute with visual feedback
4. **Review results** - Color-coded pass/fail with execution timing
5. **Explore Activity 3**: Visit `/vulnerable-demo` and `/secure-demo` for educational content

### 🔧 **For Development Testing:**
1. **Run unit tests**: `dotnet test --verbosity normal`
2. **View detailed results**: 72 automated tests with comprehensive coverage
3. **API testing**: Use `.\test-auth-api.ps1` for endpoint validation

### 📱 **For Mobile Testing:**
- **Responsive design** works perfectly on mobile devices
- **Touch-friendly interface** with large buttons and clear typography
- **Mobile-optimized layouts** for all screen sizes

## 🔧 API Testing

Use the included PowerShell script for comprehensive API testing:

```bash
.\test-auth-api.ps1
```

This script tests:
- User registration with different roles
- Login and logout flows  
- Permission verification
- Failed login scenarios
- Admin functions

## 🛠️ Configuration Features

### HTTPS Configuration
- **Development**: HTTP on port 5000 (no HTTPS warnings)
- **Production**: HTTPS redirection enabled
- **Certificates**: Developer certificate support included
- **Flexible**: Easy to switch between HTTP/HTTPS modes

### Database Configuration  
- **In-Memory**: SQLite in-memory for development/testing
- **Persistent**: Easy switch to file-based or SQL Server
- **Migrations**: Entity Framework migrations ready
- **Seeding**: Demo data automatically created

## 🎓 Complete Learning Outcomes

By completing both activities, you have implemented:

### Activity 1 - Secure Coding Practices
✅ **Input validation** preventing malicious character injection  
✅ **Parameterized queries** eliminating SQL injection  
✅ **XSS protection** through encoding and validation  
✅ **Comprehensive testing** simulating real attacks  
✅ **Defense-in-depth** security principles  

### Activity 2 - Authentication & Authorization  
✅ **Secure authentication** with BCrypt password hashing  
✅ **Role-based authorization** with granular permissions  
✅ **Session management** with secure session handling  
✅ **Account security** with locking and unlocking  
✅ **Enterprise-grade** security architecture  

### Activity 3 - Security Debugging & Hardening ⭐ **NEW!**
✅ **Vulnerability detection** with comprehensive attack pattern recognition  
✅ **Security hardening** through enhanced input validation and sanitization  
✅ **Educational platform** with vulnerability and secure implementation demos  
✅ **CSRF protection** with anti-forgery tokens and secure headers  
✅ **Attack simulation** for learning and testing purposes

## 🔗 Project Complete - All Activities Implemented

This complete security platform now includes all three activities:
- **Activity 1**: Secure coding practices and input validation
- **Activity 2**: Authentication and authorization systems  
- **Activity 3**: Security debugging, vulnerability detection, and hardening

The SafeVault platform is now a comprehensive educational and production-ready security demonstration system!

## 🛠️ Key Technologies Used

- **ASP.NET Core 9.0** - Modern web framework with Razor Pages
- **Entity Framework Core** - ORM with parameterized queries
- **BCrypt.Net-Next** - Secure password hashing
- **Bootstrap 5.3.0** - Modern responsive CSS framework
- **Font Awesome 6.0.0** - Professional icon library
- **NUnit** - Comprehensive testing framework  
- **SQLite/In-Memory Database** - Development and testing
- **Role-Based Access Control** - Enterprise authorization
- **Session Management** - Secure user sessions
- **Razor Pages** - Server-side rendering for interactive dashboard
- **Anti-forgery Tokens** - CSRF protection
- **Regex Pattern Matching** - Advanced input validation
- **HTML Encoding** - XSS prevention

## 📝 Important Security Notes

- **Password Security**: All passwords hashed with BCrypt (cost factor 12)
- **Session Security**: GUID-based sessions with 24-hour expiration
- **Account Protection**: Automatic locking after 5 failed attempts
- **Input Validation**: Multi-layer validation at all entry points
- **Database Security**: All queries parameterized through Entity Framework
- **Role Enforcement**: Strict role-based access control throughout
- **Audit Logging**: Comprehensive security event logging
- **HTTPS Ready**: Production-ready HTTPS configuration

---

## 🎉 Project Status: Complete - All Three Activities Implemented

**Activities 1, 2, and 3 successfully implemented with comprehensive security platform!**

This SafeVault application now provides:
- ✅ **Enhanced Interactive Security Dashboard** with 52 real-time tests
- ✅ **Activity 3 Vulnerability Detection** with educational demos
- ✅ **Comprehensive Security Hardening** with enhanced protection
- ✅ **Professional web interface** with Bootstrap 5.3 and responsive design
- ✅ **Visual feedback system** with color-coded results and timing
- ✅ **Enterprise-grade security** against common vulnerabilities
- ✅ **Complete authentication system** with secure password handling  
- ✅ **Comprehensive authorization** with role-based access control
- ✅ **124 total security tests** (52 interactive + 72 unit tests)
- ✅ **Production-ready configuration** with HTTPS support
- ✅ **Mobile-responsive design** that works on all devices
- ✅ **Pure C#/Razor implementation** without JavaScript dependencies
- ✅ **Educational security platform** for learning and demonstration

### 🎯 **Perfect for:**
- **Security education** with vulnerability demonstrations and secure examples
- **Professional presentations** with comprehensive, visual security testing
- **Development and testing** with 124 tests across all security domains
- **Production deployment** with enterprise-grade security measures
- **Learning platform** for understanding common vulnerabilities and their fixes

The SafeVault security platform is now complete with all three activities implemented, providing comprehensive security coverage from input validation to advanced threat detection and hardening! 🚀🛡️🎓
