# Communication_LTD Web Application

## Overview

Communication_LTD is a web-based information system designed for managing users and clients of an imaginary communication company. The application allows users to register, login, reset their password, and manage client information, including adding, updating, and searching for clients.

## Features

- User Registration and Login
- Password Reset via Email
- Add, Update, and Search Clients
- Secure Password Storage with Salted Hashing
- Protection against Common Password Attacks
- Session Management with Flask

## Technologies Used

- Python with Flask
- MySQL
- Flask-Mail for Email Handling
- dotenv for Environment Variables
- HTML, CSS, and JavaScript for Frontend

## Setup Instructions

### Prerequisites

- Python 3.x
- MySQL Server
- An Email Account for SMTP Configuration (e.g., Yahoo, Outlook)

### Create .env File -
SECRET_KEY=your_secret_key
MYSQL_HOST=localhost
MYSQL_USER=root
MYSQL_PASSWORD=your_mysql_password
MYSQL_DB=Communication_LTD
MAIL_SERVER=smtp.your_email_provider.com
MAIL_PORT=587
MAIL_USE_TLS=True
MAIL_USERNAME=your_email@example.com
MAIL_PASSWORD=your_email_password
MAIL_DEFAULT_SENDER=your_email@example.com

### Create Database Schema
CREATE DATABASE Communication_LTD;

USE Communication_LTD;

CREATE TABLE users (
    id INT AUTO_INCREMENT PRIMARY KEY,
    username VARCHAR(50) NOT NULL,
    email VARCHAR(100) NOT NULL UNIQUE,
    password_hash VARCHAR(64) NOT NULL,
    salt VARCHAR(32) NOT NULL,
    reset_token VARCHAR(40),
    failed_attempts INT DEFAULT 0,
    is_locked BOOLEAN DEFAULT FALSE
);

CREATE TABLE clients (
    id INT AUTO_INCREMENT PRIMARY KEY,
    first_name VARCHAR(50) NOT NULL,
    last_name VARCHAR(50) NOT NULL,
    cell_phone VARCHAR(15) NOT NULL,
    browsing_package ENUM('basic', 'premium') NOT NULL
);

### Installation

1. **Clone the Repository**
   ```sh
   git clone https://github.com/yourusername/Communication_LTD.git
   cd Communication_LTD
   
### Run the Application
   python main.py
