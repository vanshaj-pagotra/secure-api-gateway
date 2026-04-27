CREATE DATABASE IF NOT EXISTS demo_backend_db;
USE demo_backend_db;

CREATE TABLE IF NOT EXISTS books (
    id INT AUTO_INCREMENT PRIMARY KEY,
    title VARCHAR(200) NOT NULL,
    author VARCHAR(100) NOT NULL,
    description TEXT
);

CREATE TABLE IF NOT EXISTS demo_users (
    id INT AUTO_INCREMENT PRIMARY KEY,
    username VARCHAR(100) NOT NULL,
    email VARCHAR(150) NOT NULL,
    role ENUM('User', 'Admin') DEFAULT 'User',
    joined DATE
);

-- Sample data
INSERT INTO books (title, author, description) VALUES
('The Web Application Hacker''s Handbook', 'Stuttard & Pinto', 'Deep dive into web vulnerabilities'),
('OWASP Testing Guide', 'OWASP Foundation', 'Comprehensive web security testing guide'),
('Hacking: The Art of Exploitation', 'Jon Erickson', 'Low-level exploitation techniques'),
('The Tangled Web', 'Michal Zalewski', 'Security of web browsers');

INSERT INTO demo_users (username, email, role, joined) VALUES
('alice', 'alice@example.com', 'User', '2024-01-15'),
('bob', 'bob@example.com', 'User', '2024-02-20'),
('charlie', 'charlie@example.com', 'Admin', '2024-01-01');