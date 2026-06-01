CREATE TABLE IF NOT EXISTS users (
    id INT AUTO_INCREMENT PRIMARY KEY,
    username VARCHAR(255) UNIQUE NOT NULL,
    password_hash VARCHAR(255) NOT NULL
);

CREATE TABLE IF NOT EXISTS tickets (
    id INT AUTO_INCREMENT PRIMARY KEY,
    title VARCHAR(255) NOT NULL,
    description TEXT,
    severity VARCHAR(20) NOT NULL DEFAULT 'Low',
    status VARCHAR(20) NOT NULL DEFAULT 'Open',
    created_by VARCHAR(255) NOT NULL,
    created_at VARCHAR(50) NOT NULL,
    updated_at VARCHAR(50)
);
