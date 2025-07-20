# go-web – Go Web API with JWT Authentication

A simple web application built in **Go (Golang)** using:
- [Gin](https://github.com/gin-gonic/gin) for the HTTP web framework
- [GORM](https://gorm.io/) with SQLite for database access
- JWT-based authentication
- Password hashing with bcrypt

---

## **Features**
- **User Registration** (`POST /register`)
- **User Login** (`POST /login`) – returns a JWT token
- **Protected Endpoint** (`GET /protected`) – requires a valid Bearer token
- Integration tests (register → login → access protected endpoint)
- Modular structure with `Makefile` and `.gitignore`

---

## **Project Structure**
```
go-web/
├── Makefile # Common commands (run, build, test, etc.)
├── .gitignore # Ignore DB files and build artifacts
├── go.mod # Go module definition
├── go.sum # Dependency checksums
├── main.go # Entry point
├── router.go # Route configuration
├── handlers.go # HTTP handlers
├── auth.go # JWT & password utilities
├── models.go # GORM models (User)
├── main_test.go # Unit and integration tests
└── database.db # SQLite database (ignored by git)
```
---

## **Getting Started**

### **1. Clone the Repository**
```bash
git clone https://github.com/yourusername/go-web.git
cd go-web
```
### **2. Initialize & Tidy Modules**
```
go mod tidy
```
### **3. Run application server**
```
make run
```
The server will start at: http://localhost:8080
---
## **API Endpoints**
### Register
```
POST /register
Content-Type: application/json

{
    "username": "testuser",
    "password": "secret"
}
```
### Login
```
POST /login
Content-Type: application/json

{
    "username": "testuser",
    "password": "secret"
}
```
will generate your token.

### Protected
```
GET /protected
Authorization: Bearer <your.jwt.token>
```

### Testing
```
make test
```
---
## Makefile commands
| Command      | Description            |
| ------------ | ---------------------- |
| `make run`   | Run the application    |
| `make test`  | Run all tests          |
| `make build` | Build the binary       |
| `make tidy`  | Clean and tidy modules |
| `make clean` | Remove build artifacts |

## License
MIT