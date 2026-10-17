# RBAC Backend API

A Spring Boot REST API for authentication and role-based access control (RBAC). It provides JWT authentication, user management, roles, and permissions, with authorization enforced using permissions assigned to roles.

## Features

- User registration and login with BCrypt password hashing.
- Short-lived access tokens and rotating refresh tokens.
- Logout that revokes refresh tokens and blacklists the current access token.
- Role and permission management with safeguards against privilege escalation.
- User self-service profile/password operations and administrator user management.
- Login rate limiting by email and IP using Redis.
- OpenAPI documentation through Swagger UI.

## Technology

- Java 21 and Spring Boot 3
- Spring Web, Spring Security, Spring Data JPA, and Bean Validation
- MySQL for persistent storage; H2 is available as an alternate profile
- Redis for login rate limiting and token blacklist support
- Flyway and Hibernate for database management
- Maven

## Run locally

You will need Java 21, MySQL, and Redis. The default `dev` profile uses a local MySQL database named `default` and Redis on `localhost:6379`.

1. Create the MySQL database and make sure MySQL and Redis are running.
2. Configure the following environment variables (for example, in a local `.env` file):

   | Variable | Purpose |
   | --- | --- |
   | `DB_USERNAME` | MySQL username |
   | `DB_PASSWORD` | MySQL password |
   | `JWT_SECRET` | Secret used to sign JWTs; use a strong secret |
   | `BOOTSTRAP_ADMIN_EMAIL` | Optional initial administrator email |
   | `BOOTSTRAP_ADMIN_PASSWORD` | Optional initial administrator password |

   The bootstrap administrator is created only when both bootstrap credentials are set and no administrator exists. Keep these credentials out of source control.
3. From this directory, start the application:

   ```bash
   # Windows
   .\mvnw.cmd spring-boot:run

   # macOS/Linux
   ./mvnw spring-boot:run
   ```

The default profile is `dev`. To select another profile, set `SPRING_PROFILES_ACTIVE` to `h2`, `docker`, or `railway` before starting the application. The `docker` and `railway` profiles expect their corresponding database/Redis environment and service configuration; see `src/main/resources/application-*.properties`.

To run tests:

```bash
.\mvnw.cmd test
```

## Authentication

Registration, login, and refresh-token endpoints are public. All other API endpoints require a valid access token, except where noted in the endpoint list.

Send the access token in the standard bearer header:

```http
Authorization: Bearer <accessToken>
```

Login returns `accessToken` and `refreshToken`. Refresh tokens are single-use: `POST /api/v1/auth/refresh-token` returns a replacement pair and consumes the submitted refresh token. Logout revokes refresh tokens for that account and invalidates the current access token.

## RBAC model

Users can have roles, and roles have permissions. The API checks permission authorities on protected operations. The caller can only assign roles or permissions within the privileges they already hold.

On startup, the application synchronizes the permission records with the permissions declared in `Perm`, creates the built-in `SUPER_ADMIN` and `USER` roles when missing, and ensures `SUPER_ADMIN` has all declared permissions. Registration assigns the default `USER` role.

Available permissions:

| Area | Permissions |
| --- | --- |
| Users | `USER_READ`, `USER_UPDATE`, `USER_DELETE`, `USER_ASSIGN_ROLE` |
| Roles | `ROLE_READ`, `ROLE_CREATE`, `ROLE_UPDATE`, `ROLE_DELETE` |

`SUPER_ADMIN` is a protected system role. Roles cannot be deleted while assigned to users, and operations that would remove the last super administrator are rejected.

## API endpoints

All paths are relative to `http://localhost:8080`. Protected endpoints require a bearer access token.

### Authentication — `/api/v1/auth`

| Method | Path | Access | Description |
| --- | --- | --- | --- |
| `POST` | `/register` | Public | Register a user with the default `USER` role |
| `POST` | `/login` | Public | Authenticate and issue an access/refresh token pair |
| `POST` | `/refresh-token` | Public | Rotate a refresh token and issue a new token pair |
| `POST` | `/logout` | Authenticated | Revoke refresh tokens and blacklist the current access token |

### Roles — `/api/v1/roles`

| Method | Path | Required permission | Description |
| --- | --- | --- | --- |
| `GET` | `/` | `ROLE_READ` | List roles and their permissions |
| `GET` | `/{id}` | `ROLE_READ` | Get a role |
| `POST` | `/` | `ROLE_CREATE` | Create a role, optionally with permissions |
| `PATCH` | `/{id}` | `ROLE_UPDATE` | Update a role's name or description |
| `PUT` | `/{id}/permissions` | `ROLE_UPDATE` | Replace a role's permissions |
| `DELETE` | `/{id}` | `ROLE_DELETE` | Delete an unprotected, unassigned role |

### Permissions — `/api/v1/permissions`

| Method | Path | Required permission | Description |
| --- | --- | --- | --- |
| `GET` | `/` | `ROLE_READ` | List available permissions |

### Users — `/api/v1/users`

| Method | Path | Access | Description |
| --- | --- | --- | --- |
| `GET` | `/` | `USER_READ` | List users |
| `GET` | `/{id}` | `USER_READ` | Get a user |
| `PATCH` | `/{id}/update` | `USER_UPDATE` | Update a user's name or email |
| `DELETE` | `/{id}` | `USER_DELETE` | Delete a user and revoke their refresh tokens |
| `PUT` | `/{id}/roles` | `USER_ASSIGN_ROLE` | Replace a user's roles |
| `GET` | `/me` | Authenticated | Get the current user's profile |
| `PATCH` | `/me` | Authenticated | Update the current user's name or email |
| `PATCH` | `/me/change-password` | Authenticated | Change the current user's password; revokes refresh tokens |
| `DELETE` | `/me/{id}` | Authenticated | Delete the current user's account (the ID must match) |

Request bodies are JSON and validated by the API. For example:

```json
{
  "email": "user@example.com",
  "password": "ChangeMe123!"
}
```

## API documentation

When the application is running, Swagger UI is available at:

- `http://localhost:8080/swagger-ui.html`
- OpenAPI JSON: `http://localhost:8080/v3/api-docs`

## Project structure

```text
src/main/java/com/spring/backend/
├── module/config/       # Application, JWT, Redis, and OpenAPI configuration
├── module/security/     # Security chain, JWT filter, permissions, and helpers
├── module/user/auth/    # Registration, login, refresh, and logout
├── module/user/role/    # Role management and RBAC startup bootstrap
├── module/user/permission/ # Permission model and listing endpoint
├── module/user/token/   # Refresh token and blacklist services
├── module/user/user/    # User management and self-service endpoints
└── module/exception/    # API exception handling
```
