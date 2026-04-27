# 🔐 Secure API Gateway

A security-focused API gateway built with **FastAPI** and **MySQL**, implementing authentication, WAF, rate limiting, and security logging.

---

## ✨ Features

| Feature | Description |
|---|---|
| **JWT Authentication** | Stateless token-based auth with configurable expiry |
| **Web Application Firewall** | Regex-based detection of SQLi and XSS attacks |
| **Rate Limiting** | Fixed-window IP-based request throttling |
| **Security Logging** | All blocked requests logged to MySQL |
| **RBAC** | Role-based access control (Admin / User) |

---

## 🛠️ Tech Stack

- **Backend:** Python 3, FastAPI, Uvicorn
- **Auth:** PyJWT, Passlib (bcrypt)
- **Database:** MySQL, mysql-connector-python
- **Other:** python-dotenv, httpx

---

## ⚙️ Setup

### 1. Clone and create virtual environment
```bash
git clone https://github.com/vanshaj-pagotra/secure-api-gateway.git
cd secure-api-gateway
python -m venv venv
venv\Scripts\activate        # Windows
# source venv/bin/activate   # Linux/Mac
pip install -r requirements.txt
```

### 2. Configure environment variables
Create a `.env` file in the project root:
```ini
JWT_SECRET_KEY=your_secret_key_here
JWT_ALGORITHM=HS256
JWT_EXPIRY_MINUTES=30

DB_HOST=localhost
DB_PORT=3306
DB_NAME=secure_gateway_db
DB_USER=root
DB_PASSWORD=your_mysql_password

BACKEND_URL=http://localhost:5000

RATE_LIMIT_MAX_REQUESTS=10
RATE_LIMIT_WINDOW_SECONDS=60
```

### 3. Set up the database
```bash
mysql -u root -p < schema.sql
```

### 4. Run the server
```bash
uvicorn main:app --reload
```

The API will be available at `http://127.0.0.1:8000`

---

## 📡 API Endpoints

| Method | Endpoint | Auth Required | Description |
|---|---|---|---|
| GET | `/` | No | Health check |
| POST | `/login` | No | Authenticate and receive JWT |

---

## 📁 Project Structure

```
secure-api-gateway/
├── main.py           # FastAPI entry point and routes
├── auth.py           # Password hashing and JWT creation
├── database.py       # MySQL connection handler
├── waf.py            # Web Application Firewall (SQLi/XSS)
├── rate_limiter.py   # IP-based request throttling
├── logger.py         # Security event logging
├── schema.sql        # Database schema
└── requirements.txt  # Python dependencies
```

---

## 🔒 Security Design

- Passwords stored as **bcrypt hashes** — never plain text
- JWT tokens signed with a **secret key** from environment variables
- WAF inspects URI, headers, and request body for attack patterns
- All sensitive config loaded from `.env` — **never hardcoded**
