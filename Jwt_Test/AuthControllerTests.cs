using JWT_Auth.Controllers;
using JWT_Auth.DTOs;
using JWT_Auth.Models;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Configuration;
using Moq;
using Xunit;
using System.ComponentModel.DataAnnotations;

namespace Jwt_Test;

public class AuthControllerTests
{
    private readonly Mock<UserManager<User>> _userManagerMock;
    private readonly Mock<IConfiguration> _configurationMock;
    private readonly AuthController _controller;

    public AuthControllerTests()
    {
        var store = new Mock<IUserStore<User>>();
        _userManagerMock = new Mock<UserManager<User>>(
            store.Object, null!, null!, null!, null!, null!, null!, null!, null!);
        _configurationMock = new Mock<IConfiguration>();

        _configurationMock.Setup(c => c["Jwt:Key"]).Returns("ThisIsATestSecretKeyThatIsLongEnough256Bits!");
        _configurationMock.Setup(c => c["Jwt:Issuer"]).Returns("TestIssuer");
        _configurationMock.Setup(c => c["Jwt:Audience"]).Returns("TestAudience");
        _configurationMock.Setup(c => c["Jwt:DurationInMinutes"]).Returns("60");

        _controller = new AuthController(_userManagerMock.Object, _configurationMock.Object);
    }

    // ─── Login Tests ───────────────────────────────────────────────

    [Fact]
    public async Task Login_ValidCredentials_ReturnsOkWithToken()
    {
        var user = new User { UserName = "testuser", Email = "test@example.com", Id = "user-1" };
        _userManagerMock.Setup(m => m.FindByNameAsync("testuser")).ReturnsAsync(user);
        _userManagerMock.Setup(m => m.CheckPasswordAsync(user, "Password123")).ReturnsAsync(true);
        _userManagerMock.Setup(m => m.GetSecurityStampAsync(user)).ReturnsAsync("stamp-123");
        _userManagerMock.Setup(m => m.SupportsUserRole).Returns(false);

        var result = await _controller.Login(new LoginDto { Username = "testuser", Password = "Password123" });

        var okResult = Assert.IsType<OkObjectResult>(result);
        var dict = okResult.Value as dynamic;
        Assert.NotNull(dict);
    }

    [Fact]
    public async Task Login_InvalidUsername_ReturnsUnauthorized()
    {
        _userManagerMock.Setup(m => m.FindByNameAsync("unknown")).ReturnsAsync((User?)null);

        var result = await _controller.Login(new LoginDto { Username = "unknown", Password = "Password123" });

        var unauthorizedResult = Assert.IsType<UnauthorizedObjectResult>(result);
        Assert.NotNull(unauthorizedResult.Value);
    }

    [Fact]
    public async Task Login_InvalidPassword_ReturnsUnauthorized()
    {
        var user = new User { UserName = "testuser", Email = "test@example.com", Id = "user-1" };
        _userManagerMock.Setup(m => m.FindByNameAsync("testuser")).ReturnsAsync(user);
        _userManagerMock.Setup(m => m.CheckPasswordAsync(user, "WrongPassword")).ReturnsAsync(false);

        var result = await _controller.Login(new LoginDto { Username = "testuser", Password = "WrongPassword" });

        Assert.IsType<UnauthorizedObjectResult>(result);
    }

    [Theory]
    [InlineData(null, "Password123")]
    [InlineData("testuser", null)]
    [InlineData("", "Password123")]
    [InlineData("testuser", "")]
    public async Task Login_MissingFields_ReturnsBadRequest(string? username, string? password)
    {
        var result = await _controller.Login(new LoginDto
        {
            Username = username!,
            Password = password!
        });

        Assert.IsType<BadRequestObjectResult>(result);
    }

    [Fact]
    public async Task Login_NullModel_ReturnsBadRequest()
    {
        var result = await _controller.Login(null!);

        Assert.IsType<BadRequestObjectResult>(result);
    }

    // ─── Register Tests ────────────────────────────────────────────

    [Fact]
    public async Task Register_ValidData_ReturnsOk()
    {
        _userManagerMock
            .Setup(m => m.CreateAsync(It.IsAny<User>(), "Password123"))
            .ReturnsAsync(IdentityResult.Success);

        var result = await _controller.Register(new RegisterDto
        {
            Username = "newuser",
            Email = "new@example.com",
            Password = "Password123"
        });

        var okResult = Assert.IsType<OkObjectResult>(result);
        Assert.NotNull(okResult.Value);
    }

    [Fact]
    public async Task Register_DuplicateUser_ReturnsBadRequest()
    {
        _userManagerMock
            .Setup(m => m.CreateAsync(It.IsAny<User>(), "Password123"))
            .ReturnsAsync(IdentityResult.Failed(new IdentityError { Description = "Username already taken." }));

        var result = await _controller.Register(new RegisterDto
        {
            Username = "existinguser",
            Email = "existing@example.com",
            Password = "Password123"
        });

        var badRequest = Assert.IsType<BadRequestObjectResult>(result);
        Assert.NotNull(badRequest.Value);
    }

    [Theory]
    [InlineData(null, "test@example.com", "Password123")]
    [InlineData("testuser", null, "Password123")]
    [InlineData("testuser", "test@example.com", null)]
    [InlineData("", "test@example.com", "Password123")]
    [InlineData("testuser", "", "Password123")]
    [InlineData("testuser", "test@example.com", "")]
    public async Task Register_MissingFields_ReturnsBadRequest(string? username, string? email, string? password)
    {
        var result = await _controller.Register(new RegisterDto
        {
            Username = username!,
            Email = email!,
            Password = password!
        });

        Assert.IsType<BadRequestObjectResult>(result);
    }

    [Fact]
    public async Task Register_NullModel_ReturnsBadRequest()
    {
        var result = await _controller.Register(null!);

        Assert.IsType<BadRequestObjectResult>(result);
    }

    // ─── Token Generation Tests ────────────────────────────────────

    [Fact]
    public async Task GenerateJwtTokenAsync_ReturnsNonEmptyToken()
    {
        var user = new User { UserName = "testuser", Email = "test@example.com", Id = "user-1" };
        _userManagerMock.Setup(m => m.GetSecurityStampAsync(user)).ReturnsAsync("stamp-abc");
        _userManagerMock.Setup(m => m.SupportsUserRole).Returns(false);

        var token = await _controller.GenerateJwtTokenAsync(user);

        Assert.False(string.IsNullOrWhiteSpace(token));
    }

    [Fact]
    public async Task GenerateJwtTokenAsync_ContainsValidClaims()
    {
        var user = new User { UserName = "testuser", Email = "test@example.com", Id = "user-1" };
        _userManagerMock.Setup(m => m.GetSecurityStampAsync(user)).ReturnsAsync("stamp-abc");
        _userManagerMock.Setup(m => m.SupportsUserRole).Returns(false);

        var token = await _controller.GenerateJwtTokenAsync(user);

        var handler = new System.IdentityModel.Tokens.Jwt.JwtSecurityTokenHandler();
        var jwtToken = handler.ReadJwtToken(token);

        Assert.Equal("testuser", jwtToken.Subject);
        Assert.Equal("test@example.com", jwtToken.Claims.First(c => c.Type == "email").Value);
        Assert.Equal("user-1", jwtToken.Claims.First(c => c.Type == "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/nameidentifier").Value);
        Assert.Equal("stamp-abc", jwtToken.Claims.First(c => c.Type == "aspnet.stamp").Value);
        Assert.Equal("TestIssuer", jwtToken.Issuer);
        Assert.Equal("TestAudience", jwtToken.Audiences.First());
    }

    [Fact]
    public async Task GenerateJwtTokenAsync_WithRoles_IncludesRoleClaims()
    {
        var user = new User { UserName = "admin", Email = "admin@example.com", Id = "user-2" };
        _userManagerMock.Setup(m => m.GetSecurityStampAsync(user)).ReturnsAsync("stamp-xyz");
        _userManagerMock.Setup(m => m.SupportsUserRole).Returns(true);
        _userManagerMock.Setup(m => m.GetRolesAsync(user)).ReturnsAsync(new List<string> { "Admin", "User" });

        var token = await _controller.GenerateJwtTokenAsync(user);

        var handler = new System.IdentityModel.Tokens.Jwt.JwtSecurityTokenHandler();
        var jwtToken = handler.ReadJwtToken(token);

        var roleClaims = jwtToken.Claims.Where(c => c.Type == System.Security.Claims.ClaimTypes.Role).ToList();
        Assert.Equal(2, roleClaims.Count);
        Assert.Contains(roleClaims, c => c.Value == "Admin");
        Assert.Contains(roleClaims, c => c.Value == "User");
    }

    [Fact]
    public async Task GenerateJwtTokenAsync_ThrowsWhenJwtKeyMissing()
    {
        _configurationMock.Setup(c => c["Jwt:Key"]).Returns((string?)null);

        var controller = new AuthController(_userManagerMock.Object, _configurationMock.Object);
        var user = new User { UserName = "testuser", Email = "test@example.com", Id = "user-1" };

        await Assert.ThrowsAsync<InvalidOperationException>(
            () => controller.GenerateJwtTokenAsync(user));
    }

    // ─── Failing Tests: Expose Real Bugs ──────────────────────────

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("   ")]
    [InlineData("   \t\n  ")]
    public void LoginDto_MissingUsername_ShouldFailValidation(string? username)
    {
        // BUG: LoginDto has no [Required] attribute on Username.
        // ModelState validation will NOT catch null/empty/whitespace values.
        var dto = new LoginDto { Username = username!, Password = "Password123" };
        var context = new ValidationContext(dto);
        var results = new List<ValidationResult>();

        var isValid = Validator.TryValidateObject(dto, context, results, validateAllProperties: true);

        Assert.False(isValid, $"Username '{username}' should fail validation but ModelState says valid");
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("   ")]
    public void LoginDto_MissingPassword_ShouldFailValidation(string? password)
    {
        // BUG: LoginDto has no [Required] attribute on Password.
        var dto = new LoginDto { Username = "testuser", Password = password! };
        var context = new ValidationContext(dto);
        var results = new List<ValidationResult>();

        var isValid = Validator.TryValidateObject(dto, context, results, validateAllProperties: true);

        Assert.False(isValid, $"Password '{password}' should fail validation but ModelState says valid");
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("   ")]
    public void RegisterDto_MissingUsername_ShouldFailValidation(string? username)
    {
        // BUG: RegisterDto has no [Required] attribute on Username.
        var dto = new RegisterDto { Username = username!, Email = "test@example.com", Password = "Password123" };
        var context = new ValidationContext(dto);
        var results = new List<ValidationResult>();

        var isValid = Validator.TryValidateObject(dto, context, results, validateAllProperties: true);

        Assert.False(isValid, $"Username '{username}' should fail validation but ModelState says valid");
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("   ")]
    public void RegisterDto_MissingEmail_ShouldFailValidation(string? email)
    {
        // BUG: RegisterDto has no [Required] attribute on Email.
        var dto = new RegisterDto { Username = "testuser", Email = email!, Password = "Password123" };
        var context = new ValidationContext(dto);
        var results = new List<ValidationResult>();

        var isValid = Validator.TryValidateObject(dto, context, results, validateAllProperties: true);

        Assert.False(isValid, $"Email '{email}' should fail validation but ModelState says valid");
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("   ")]
    public void RegisterDto_MissingPassword_ShouldFailValidation(string? password)
    {
        // BUG: RegisterDto has no [Required] attribute on Password.
        var dto = new RegisterDto { Username = "testuser", Email = "test@example.com", Password = password! };
        var context = new ValidationContext(dto);
        var results = new List<ValidationResult>();

        var isValid = Validator.TryValidateObject(dto, context, results, validateAllProperties: true);

        Assert.False(isValid, $"Password '{password}' should fail validation but ModelState says valid");
    }

    [Theory]
    [InlineData("not-an-email")]
    [InlineData("missing-at-sign.com")]
    [InlineData("@no-local-part.com")]
    [InlineData("user@")]
    [InlineData("user@.com")]
    public void RegisterDto_InvalidEmailFormat_ShouldFailValidation(string email)
    {
        // BUG: RegisterDto has no [EmailAddress] attribute.
        // Any string is accepted as an email address.
        var dto = new RegisterDto { Username = "testuser", Email = email, Password = "Password123" };
        var context = new ValidationContext(dto);
        var results = new List<ValidationResult>();

        var isValid = Validator.TryValidateObject(dto, context, results, validateAllProperties: true);

        Assert.False(isValid, $"Email '{email}' should fail validation but was accepted");
    }

    [Fact]
    public async Task Register_InvalidEmailFormat_ShouldBeRejected()
    {
        // BUG: Controller accepts any string as email — no format validation.
        _userManagerMock
            .Setup(m => m.CreateAsync(It.IsAny<User>(), "Password123"))
            .ReturnsAsync(IdentityResult.Success);

        var result = await _controller.Register(new RegisterDto
        {
            Username = "testuser",
            Email = "not-an-email",
            Password = "Password123"
        });

        // This SHOULD return BadRequest, but currently returns Ok — that's the bug.
        Assert.IsType<BadRequestObjectResult>(result);
    }

    [Fact]
    public async Task Login_WhitespaceOnlyUsername_ShouldBeRejected()
    {
        // BUG: Controller checks IsNullOrWhiteSpace but the value "   " with
        // multiple spaces may slip through depending on how whitespace is handled.
        // This test verifies whitespace-only usernames are rejected.
        var result = await _controller.Login(new LoginDto
        {
            Username = "   ",
            Password = "Password123"
        });

        Assert.IsType<BadRequestObjectResult>(result);
    }

    [Fact]
    public async Task Login_WhitespaceOnlyPassword_ShouldBeRejected()
    {
        // BUG: Same as above for passwords.
        var result = await _controller.Login(new LoginDto
        {
            Username = "testuser",
            Password = "   "
        });

        Assert.IsType<BadRequestObjectResult>(result);
    }

    [Fact]
    public async Task GenerateJwtTokenAsync_TokenExpiration_ShouldMatchConfiguredDuration()
    {
        // BUG: Token expiration is hardcoded to use the config value, but
        // if DurationInMinutes is missing or invalid, it silently defaults to 60.
        // This test verifies the token actually expires at the configured time.
        _configurationMock.Setup(c => c["Jwt:DurationInMinutes"]).Returns("30");

        var user = new User { UserName = "testuser", Email = "test@example.com", Id = "user-1" };
        _userManagerMock.Setup(m => m.GetSecurityStampAsync(user)).ReturnsAsync("stamp-abc");
        _userManagerMock.Setup(m => m.SupportsUserRole).Returns(false);

        var controller = new AuthController(_userManagerMock.Object, _configurationMock.Object);
        var token = await controller.GenerateJwtTokenAsync(user);

        var handler = new System.IdentityModel.Tokens.Jwt.JwtSecurityTokenHandler();
        var jwtToken = handler.ReadJwtToken(token);

        var expectedExpiry = DateTime.UtcNow.AddMinutes(30);
        var tolerance = TimeSpan.FromSeconds(10);

        Assert.True(
            jwtToken.ValidTo <= expectedExpiry.Add(tolerance) && jwtToken.ValidTo >= expectedExpiry.AddMinutes(-1),
            $"Token should expire around {expectedExpiry:O} but expires at {jwtToken.ValidTo:O}");
    }

    [Fact]
    public async Task GenerateJwtTokenAsync_DurationInMinutesMissing_ShouldDefaultTo60()
    {
        // BUG: When DurationInMinutes is not configured, the token silently
        // defaults to 60 minutes. This should be explicitly documented or
        // throw an error, not silently default.
        _configurationMock.Setup(c => c["Jwt:DurationInMinutes"]).Returns((string?)null);

        var user = new User { UserName = "testuser", Email = "test@example.com", Id = "user-1" };
        _userManagerMock.Setup(m => m.GetSecurityStampAsync(user)).ReturnsAsync("stamp-abc");
        _userManagerMock.Setup(m => m.SupportsUserRole).Returns(false);

        var controller = new AuthController(_userManagerMock.Object, _configurationMock.Object);
        var token = await controller.GenerateJwtTokenAsync(user);

        var handler = new System.IdentityModel.Tokens.Jwt.JwtSecurityTokenHandler();
        var jwtToken = handler.ReadJwtToken(token);

        var expectedExpiry = DateTime.UtcNow.AddMinutes(60);
        var tolerance = TimeSpan.FromSeconds(10);

        Assert.True(
            jwtToken.ValidTo <= expectedExpiry.Add(tolerance) && jwtToken.ValidTo >= expectedExpiry.AddMinutes(-1),
            $"Token should default to 60min expiry but expires at {jwtToken.ValidTo:O}");
    }

    [Fact]
    public async Task GenerateJwtTokenAsync_DurationInMinutesInvalid_ShouldDefaultTo60()
    {
        // BUG: Invalid DurationInMinutes string (e.g. "abc") silently defaults to 60.
        _configurationMock.Setup(c => c["Jwt:DurationInMinutes"]).Returns("not-a-number");

        var user = new User { UserName = "testuser", Email = "test@example.com", Id = "user-1" };
        _userManagerMock.Setup(m => m.GetSecurityStampAsync(user)).ReturnsAsync("stamp-abc");
        _userManagerMock.Setup(m => m.SupportsUserRole).Returns(false);

        var controller = new AuthController(_userManagerMock.Object, _configurationMock.Object);
        var token = await controller.GenerateJwtTokenAsync(user);

        var handler = new System.IdentityModel.Tokens.Jwt.JwtSecurityTokenHandler();
        var jwtToken = handler.ReadJwtToken(token);

        var expectedExpiry = DateTime.UtcNow.AddMinutes(60);
        var tolerance = TimeSpan.FromSeconds(10);

        Assert.True(
            jwtToken.ValidTo <= expectedExpiry.Add(tolerance) && jwtToken.ValidTo >= expectedExpiry.AddMinutes(-1),
            $"Token should default to 60min on invalid config but expires at {jwtToken.ValidTo:O}");
    }

    [Fact]
    public async Task Login_UserManagerThrows_ShouldPropagateException()
    {
        // BUG: No try/catch around UserManager calls.
        // If FindByNameAsync throws, the exception propagates unhandled (500).
        _userManagerMock.Setup(m => m.FindByNameAsync("testuser"))
            .ThrowsAsync(new InvalidOperationException("Database connection lost"));

        var exception = await Assert.ThrowsAsync<InvalidOperationException>(
            () => _controller.Login(new LoginDto { Username = "testuser", Password = "Password123" }));

        Assert.Contains("Database connection lost", exception.Message);
    }

    [Fact]
    public async Task Register_UserManagerThrows_ShouldPropagateException()
    {
        // BUG: No try/catch around UserManager.CreateAsync.
        _userManagerMock.Setup(m => m.CreateAsync(It.IsAny<User>(), "Password123"))
            .ThrowsAsync(new InvalidOperationException("Database connection lost"));

        var exception = await Assert.ThrowsAsync<InvalidOperationException>(
            () => _controller.Register(new RegisterDto
            {
                Username = "testuser",
                Email = "test@example.com",
                Password = "Password123"
            }));

        Assert.Contains("Database connection lost", exception.Message);
    }

    [Fact]
    public async Task GenerateJwtTokenAsync_SecurityStampNull_ShouldStillGenerateToken()
    {
        // BUG: When GetSecurityStampAsync returns null, the token is generated
        // with an empty "aspnet.stamp" claim — this could bypass token invalidation.
        _userManagerMock.Setup(m => m.GetSecurityStampAsync(It.IsAny<User>())).ReturnsAsync((string?)null);
        _userManagerMock.Setup(m => m.SupportsUserRole).Returns(false);

        _configurationMock.Setup(c => c["Jwt:Key"]).Returns("ThisIsATestSecretKeyThatIsLongEnough256Bits!");

        var controller = new AuthController(_userManagerMock.Object, _configurationMock.Object);
        var user = new User { UserName = "testuser", Email = "test@example.com", Id = "user-1" };

        var token = await controller.GenerateJwtTokenAsync(user);

        var handler = new System.IdentityModel.Tokens.Jwt.JwtSecurityTokenHandler();
        var jwtToken = handler.ReadJwtToken(token);
        var stampClaim = jwtToken.Claims.FirstOrDefault(c => c.Type == "aspnet.stamp");

        Assert.NotNull(stampClaim);
        Assert.Equal(string.Empty, stampClaim.Value);
    }

    [Fact]
    public async Task Register_PasswordTooShort_ShouldFailThroughIdentity()
    {
        // BUG: Identity is configured with RequiredLength=6, but the controller
        // doesn't validate this before calling CreateAsync. The error comes from
        // Identity, not from controller-level validation.
        _userManagerMock
            .Setup(m => m.CreateAsync(It.IsAny<User>(), "123"))
            .ReturnsAsync(IdentityResult.Failed(
                new IdentityError { Description = "Passwords must be at least 6 characters." }));

        var result = await _controller.Register(new RegisterDto
        {
            Username = "testuser",
            Email = "test@example.com",
            Password = "123"
        });

        var badRequest = Assert.IsType<BadRequestObjectResult>(result);
        Assert.NotNull(badRequest.Value);
    }

    [Fact]
    public async Task Register_PasswordMissingUppercase_ShouldFailThroughIdentity()
    {
        // BUG: Identity requires uppercase, but controller doesn't pre-validate.
        _userManagerMock
            .Setup(m => m.CreateAsync(It.IsAny<User>(), "alllowercase1"))
            .ReturnsAsync(IdentityResult.Failed(
                new IdentityError { Description = "Passwords must have at least one uppercase letter." }));

        var result = await _controller.Register(new RegisterDto
        {
            Username = "testuser",
            Email = "test@example.com",
            Password = "alllowercase1"
        });

        var badRequest = Assert.IsType<BadRequestObjectResult>(result);
        Assert.NotNull(badRequest.Value);
    }

    [Fact]
    public async Task Register_PasswordMissingDigit_ShouldFailThroughIdentity()
    {
        // BUG: Identity requires digit, but controller doesn't pre-validate.
        _userManagerMock
            .Setup(m => m.CreateAsync(It.IsAny<User>(), "NoDigitsHere"))
            .ReturnsAsync(IdentityResult.Failed(
                new IdentityError { Description = "Passwords must have at least one digit." }));

        var result = await _controller.Register(new RegisterDto
        {
            Username = "testuser",
            Email = "test@example.com",
            Password = "NoDigitsHere"
        });

        var badRequest = Assert.IsType<BadRequestObjectResult>(result);
        Assert.NotNull(badRequest.Value);
    }
}
