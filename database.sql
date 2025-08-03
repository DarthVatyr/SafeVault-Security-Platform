-- SafeVault Database Schema
-- This script creates the secure database structure for the SafeVault application

-- Enable foreign key constraints (SQLite specific)
PRAGMA foreign_keys = ON;

-- Create Users table with security constraints
CREATE TABLE IF NOT EXISTS Users (
    UserID INTEGER PRIMARY KEY AUTOINCREMENT,
    Username VARCHAR(100) NOT NULL UNIQUE,
    Email VARCHAR(100) NOT NULL UNIQUE,
    CreatedAt DATETIME DEFAULT CURRENT_TIMESTAMP,
    UpdatedAt DATETIME DEFAULT CURRENT_TIMESTAMP,
    
    -- Add constraints for data validation
    CONSTRAINT chk_username_length CHECK (LENGTH(Username) >= 3 AND LENGTH(Username) <= 100),
    CONSTRAINT chk_email_length CHECK (LENGTH(Email) >= 5 AND LENGTH(Email) <= 100),
    CONSTRAINT chk_username_format CHECK (Username NOT LIKE '%<%' AND Username NOT LIKE '%>%' 
                                         AND Username NOT LIKE '%''%' AND Username NOT LIKE '%"%'),
    CONSTRAINT chk_email_format CHECK (Email LIKE '%_@_%.__%' 
                                      AND Email NOT LIKE '%<%' AND Email NOT LIKE '%>%' 
                                      AND Email NOT LIKE '%''%' AND Email NOT LIKE '%"%')
);

-- Create indexes for performance and security
CREATE INDEX IF NOT EXISTS idx_users_username ON Users(Username);
CREATE INDEX IF NOT EXISTS idx_users_email ON Users(Email);
CREATE INDEX IF NOT EXISTS idx_users_created_at ON Users(CreatedAt);

-- Create audit table for security monitoring
CREATE TABLE IF NOT EXISTS UserAuditLog (
    AuditID INTEGER PRIMARY KEY AUTOINCREMENT,
    UserID INTEGER,
    Action VARCHAR(50) NOT NULL,
    IPAddress VARCHAR(45),
    UserAgent TEXT,
    Timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
    Details TEXT,
    
    FOREIGN KEY (UserID) REFERENCES Users(UserID) ON DELETE SET NULL
);

-- Create trigger to update UpdatedAt timestamp
CREATE TRIGGER IF NOT EXISTS update_users_timestamp 
    AFTER UPDATE ON Users
    FOR EACH ROW
BEGIN
    UPDATE Users SET UpdatedAt = CURRENT_TIMESTAMP WHERE UserID = NEW.UserID;
END;

-- Create trigger for audit logging
CREATE TRIGGER IF NOT EXISTS audit_user_insert
    AFTER INSERT ON Users
    FOR EACH ROW
BEGIN
    INSERT INTO UserAuditLog (UserID, Action, Details) 
    VALUES (NEW.UserID, 'INSERT', 'User created: ' || NEW.Username);
END;

CREATE TRIGGER IF NOT EXISTS audit_user_update
    AFTER UPDATE ON Users
    FOR EACH ROW
BEGIN
    INSERT INTO UserAuditLog (UserID, Action, Details) 
    VALUES (NEW.UserID, 'UPDATE', 'User updated: ' || NEW.Username);
END;

CREATE TRIGGER IF NOT EXISTS audit_user_delete
    AFTER DELETE ON Users
    FOR EACH ROW
BEGIN
    INSERT INTO UserAuditLog (UserID, Action, Details) 
    VALUES (OLD.UserID, 'DELETE', 'User deleted: ' || OLD.Username);
END;

-- Insert some test data (clean, validated data)
INSERT OR IGNORE INTO Users (Username, Email) VALUES 
    ('admin', 'admin@safevault.com'),
    ('testuser', 'test@example.com'),
    ('john_doe', 'john.doe@company.org');

-- Verify the setup
SELECT 'Database setup completed successfully!' AS Status;

-- Show table structure
.schema Users
.schema UserAuditLog

-- Show sample data
SELECT 'Sample Users:' AS Info;
SELECT UserID, Username, Email, CreatedAt FROM Users;
