# JWT_Auth (ASP.NET Core)

Simple ASP.NET Core project demonstrating using ASP.NET Identity for user management and issuing JWT access tokens (no cookies).

## Features
- ASP.NET Core (.NET 10) Web API
- ASP.NET Identity (EF Core stores)
- SQL Server / LocalDB support via `DefaultConnection` in `appsettings.json`
- JWT authentication (Bearer tokens)
- Security-stamp included in JWT and validated on token use (supports token invalidation)

## Quick setup (development)
1. Ensure .NET 10 SDK is installed.
2. Update the connection string in `JWT_Auth/appsettings.json` if needed. Example for LocalDB (development):

   ```
   "ConnectionStrings": {
     "DefaultConnection": "Server=(localdb)\\MSSQLLocalDB;Database=JWTAuthDb;Trusted_Connection=True;MultipleActiveResultSets=true"
   }
   ```

   If you connect to a server with an untrusted certificate (dev), you can add `TrustServerCertificate=True` to the connection string.

3. Restore and build:

   ```bash
   dotnet restore
   dotnet build
   ```

4. Create and apply EF migrations (from repository root):

   ```bash
   dotnet ef migrations add Initial --project JWT_Auth --startup-project JWT_Auth
   dotnet ef database update --project JWT_Auth --startup-project JWT_Auth
   ```

5. Run the API:

   ```bash
   dotnet run --project JWT_Auth
   ```

## API Endpoints
- POST `/api/auth/register` — register a new user. Body: `{ "username":"user", "email":"a@b.com", "password":"P@ssword1" }`.
- POST `/api/auth/login` — login. Body: `{ "username":"user", "password":"P@ssword1" }`. Returns JSON containing `Token` (JWT).

Use the returned token in `Authorization: Bearer <token>` header for protected endpoints.

## Configuration
JWT settings are in `JWT_Auth/appsettings.json` under `Jwt`:
- `Key` — symmetric signing key (keep secret in production, use secrets manager/Key Vault)
- `Issuer`, `Audience`, `DurationInMinutes`

## Notes / Security
- The project uses `UserManager<User>` and `CheckPasswordAsync` for credential validation and does not issue cookies.
- The JWT includes the user's security stamp (`aspnet.stamp`) and the JwtBearer `OnTokenValidated` event compares it with the current stamp. Changing the user's password or security-related info invalidates existing tokens.
- For production, store the signing key securely, use HTTPS, and consider refresh tokens / short token lifetimes.

## Troubleshooting
- If EF tools fail to create the DbContext at design time, either run the `dotnet ef` commands with `--project` and `--startup-project` as shown above, or add a design-time factory `AppDbContextFactory`.
- If you see SSL certificate trust errors connecting to SQL Server, consider `TrustServerCertificate=True` for development or install a trusted certificate for production.

## Packages used (high level)
- Microsoft.AspNetCore.Authentication.JwtBearer
- Microsoft.AspNetCore.Identity.EntityFrameworkCore
- Microsoft.EntityFrameworkCore.SqlServer
- Microsoft.EntityFrameworkCore.Tools

If you want, I can add a CONTRIBUTING or a script for creating the DB/migrations. 
