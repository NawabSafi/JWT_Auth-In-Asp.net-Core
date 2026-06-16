using JWT_Auth.Controllers;
using JWT_Auth.DTOs;
using JWT_Auth.Models;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Configuration;
using Moq;
using Xunit;

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
}
