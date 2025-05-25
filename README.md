# NerdsLab Backend

A Django REST API for user authentication (login/logout) connected to a frontend.

## Features

- User registration
- User login/logout
- Token-based authentication
- User profile management

## Project Structure

```
nerdslab_backend/
├── accounts/              # User authentication app
│   ├── migrations/        # Database migrations
│   ├── __init__.py
│   ├── admin.py           # Admin configuration
│   ├── apps.py            # App configuration
│   ├── models.py          # Database models
│   ├── serializers.py     # Data serializers
│   ├── tests.py           # Test cases
│   ├── urls.py            # URL routes
│   └── views.py           # API views
├── nerdslab/              # Main project directory
│   ├── __init__.py
│   ├── asgi.py            # ASGI configuration
│   ├── settings.py        # Project settings
│   ├── urls.py            # Project URL configuration
│   └── wsgi.py            # WSGI configuration
├── manage.py              # Django command-line utility
└── requirements.txt       # Project dependencies
```

## API Endpoints

### Authentication

- `POST /api/accounts/register/` - Register a new user
- `POST /api/accounts/login/` - Login a user
- `POST /api/accounts/logout/` - Logout a user
- `GET /api/accounts/me/` - Get current user information

## Installation

1. Clone the repository
2. Install dependencies: `pip install -r requirements.txt`
3. Run migrations: `python manage.py migrate`
4. Create a superuser: `python manage.py createsuperuser`
5. Run the server: `python manage.py runserver`

## Frontend Integration

### Authentication Flow

1. Register a user by sending a POST request to `/api/accounts/register/`
2. Login by sending a POST request to `/api/accounts/login/`
3. Store the returned token in local storage or cookies
4. Include the token in the Authorization header for authenticated requests: `Authorization: Token <your_token>`
5. Logout by sending a POST request to `/api/accounts/logout/`

### Example Frontend Code (JavaScript/React)

```javascript
// Register a user
async function registerUser(userData) {
  const response = await fetch('http://localhost:8000/api/accounts/register/', {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
    },
    body: JSON.stringify(userData),
  });
  
  return await response.json();
}

// Login a user
async function loginUser(credentials) {
  const response = await fetch('http://localhost:8000/api/accounts/login/', {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
    },
    body: JSON.stringify(credentials),
  });
  
  return await response.json();
}

// Get user details
async function getUserDetails(token) {
  const response = await fetch('http://localhost:8000/api/accounts/me/', {
    headers: {
      'Authorization': `Token ${token}`,
    },
  });
  
  return await response.json();
}

// Logout user
async function logoutUser(token) {
  const response = await fetch('http://localhost:8000/api/accounts/logout/', {
    method: 'POST',
    headers: {
      'Authorization': `Token ${token}`,
    },
  });
  
  return await response.json();
}
```

## Password Security

This application implements industry-standard password security best practices:

### Strong Password Hashing

- Uses Argon2 as the primary password hashing algorithm (winner of the Password Hashing Competition)
- Fall back to PBKDF2 with SHA-512 and high iteration counts for older systems
- Includes BCrypt support for comprehensive security
- Each password is automatically salted with a unique salt
- Passwords are never stored in plaintext

### Password Validation

- Enforces minimum length requirements (12 characters)
- Checks against common passwords and dictionary attacks
- Prevents usage of user attributes in passwords
- Rejects passwords with common patterns (keyboard sequences, predictable formats)
- Detects and prevents l33t speak substitutions (e.g., 'p@ssw0rd')
- Validates against simple pattern-based passwords (e.g., 'Password123')

### Auto-Rehashing

The system includes features to automatically upgrade password hashing:

- Middleware that checks and upgrades password hashing algorithms on login
- Management command (`python manage.py rehash_passwords`) to analyze password hashing status

### Implementation

- Authentication uses Django's built-in auth system with enhanced security
- Password reset tokens are time-limited and single-use
- Detailed error messages guide users to create stronger passwords

## Environment Variables and Security

This application uses environment variables to secure sensitive credentials:

### Configuration Management

- Sensitive credentials are loaded from environment variables
- Fallbacks are included for development environments
- The `.env` file is used to store these variables locally
- Easy transition from hardcoded credentials to environment variables

### Setting Up Environment Variables

1. Run the provided script to generate a `.env` file: `python generate_env.py`
2. For production, update the values in the `.env` file with secure credentials
3. Keep the `.env` file secure and never commit it to version control

### Secured Credentials

The following sensitive data is protected:
- `DJANGO_SECRET_KEY`: The secret key used for cryptographic signing
- `EMAIL_HOST_PASSWORD`: Email server authentication password
- `LAB_SERVICE_TOKEN`: API token for lab service integration

### Deployment Considerations

When deploying to production:
1. Generate a new secure `SECRET_KEY`
2. Set `DEBUG=False`
3. Configure `ALLOWED_HOSTS` properly
4. Use environment variables or a secure vault service for credentials 