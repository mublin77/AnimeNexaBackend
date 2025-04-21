using AnimeApp.Core.Models;
using AnimeApp.Core.Services;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;
using Google.Apis.Auth;

namespace AnimeApp.API.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class AuthController : ControllerBase
    {
        private readonly UserManager<IdentityUser> _userManager;
        private readonly RoleManager<IdentityRole> _roleManager;
        private readonly IConfiguration _configuration;
        private readonly AnimeApp.Infrastructure.Data.Context.AnimeAppDbContext _context;
        private readonly IEmailSender _emailSender;
        private readonly IUserProfileService _profileService;


        public AuthController(
            UserManager<IdentityUser> userManager,
            RoleManager<IdentityRole> roleManager,
            IConfiguration configuration,
            AnimeApp.Infrastructure.Data.Context.AnimeAppDbContext context,
            IEmailSender emailSender, 
            IUserProfileService profileService)
        {
            _userManager = userManager;
            _roleManager = roleManager;
            _configuration = configuration;
            _context = context;
            _emailSender = emailSender;
            _profileService = profileService;
        }

        [HttpPost("register")]
        public async Task<IActionResult> Register([FromBody] RegisterModel model)
        {
            if (!ModelState.IsValid)
            {
                var errors = ModelState.Values.SelectMany(v => v.Errors).Select(e => e.ErrorMessage);
                Serilog.Log.Warning("ModelState errors: {Errors}", string.Join(", ", errors));
                return BadRequest(new { message = "Invalid registration details.", errors });
            }

            var user = new IdentityUser { UserName = model.Username, Email = model.Email };
            var result = await _userManager.CreateAsync(user, model.Password);

            if (!result.Succeeded)
            {
                return BadRequest(new { message = "Registration failed", errors = result.Errors });
            }

            var roleName = "USER";
            if (!await _roleManager.RoleExistsAsync(roleName))
            {
                var roleResult = await _roleManager.CreateAsync(new IdentityRole(roleName));
                if (!roleResult.Succeeded)
                {
                    return StatusCode(500, "Failed to create USER role.");
                }
            }

            await _userManager.AddToRoleAsync(user, roleName);

            // Create user profile
            var profile = new UserProfile
            {
                Id = Guid.NewGuid().ToString(),
                UserId = user.Id,
                Username = model.Username,
                Bio = "",
                ProfilePhotoUrl = "",
                Links = new List<SocialLink>(),
                CreatedAt = DateTime.UtcNow,
                UpdatedAt = DateTime.UtcNow
            };
            await _profileService.CreateProfileAsync(profile);

            try
            {
                var token = await _userManager.GenerateEmailConfirmationTokenAsync(user);
                var confirmationLink = Url.Action("ConfirmEmail", "Auth", new { userId = user.Id, token }, Request.Scheme);
                await _emailSender.SendEmailAsync(model.Email, "Confirm Your AnimeApp Email", $"Please confirm your email by clicking <a href='{confirmationLink}'>here</a>.");
                Serilog.Log.Information("Confirmation email sent to {Email}", model.Email);
            }
            catch (Exception ex)
            {
                Serilog.Log.Warning(ex, "Failed to send confirmation email to {Email}", model.Email);
            }

            await _userManager.ConfirmEmailAsync(user, await _userManager.GenerateEmailConfirmationTokenAsync(user));
            return Ok(new { message = "User registered successfully." });
        }

        [HttpGet("ConfirmEmail")]
        [AllowAnonymous]
        public async Task<IActionResult> ConfirmEmail(string userId, string token)
        {
            if (string.IsNullOrEmpty(userId) || string.IsNullOrEmpty(token))
            {
                Serilog.Log.Warning("Invalid email confirmation attempt: UserId={UserId}, Token={Token}", userId, token);
                return BadRequest(new { Message = "Invalid confirmation link" });
            }

            var user = await _userManager.FindByIdAsync(userId);
            if (user == null)
            {
                Serilog.Log.Error("User not found for email confirmation: UserId={UserId}", userId);
                return NotFound(new { Message = "User not found" });
            }

            var result = await _userManager.ConfirmEmailAsync(user, token);
            if (result.Succeeded)
            {
                Serilog.Log.Information("Email confirmed successfully for user: {Email}", user.Email);
                return Ok(new { Message = "Email confirmed successfully" });
            }

            Serilog.Log.Error("Failed to confirm email: {Errors}", string.Join(", ", result.Errors.Select(e => e.Description)));
            return BadRequest(new { Message = "Email confirmation failed", Errors = result.Errors });
        }

        [HttpPost("login")]
        [AllowAnonymous]
        public async Task<IActionResult> Login([FromBody] LoginModel model)
        {
            Serilog.Log.Information("Login called: Email={Email}", model.Email);
            var loginUser = await _userManager.FindByEmailAsync(model.Email);
            if (loginUser == null || !await _userManager.CheckPasswordAsync(loginUser, model.Password))
            {
                Serilog.Log.Warning("Invalid login attempt: {Email}", model.Email);
                return Unauthorized(new { Message = "Invalid credentials" });
            }

            if (!await _userManager.IsEmailConfirmedAsync(loginUser))
            {
                Serilog.Log.Warning("Email not confirmed for user: {Email}", model.Email);
                return Unauthorized(new { Message = "Please confirm your email before logging in" });
            }

            var accessToken = await GenerateJwtToken(loginUser);
            var refreshToken = GenerateRefreshToken(loginUser.Id);
            _context.RefreshTokens.Add(refreshToken);
            try
            {
                await _context.SaveChangesAsync();
            }
            catch (DbUpdateException ex)
            {
                Serilog.Log.Error(ex, "Failed to save refresh token for user: {Email}", model.Email);
                return StatusCode(500, new { Message = "Failed to save refresh token", Error = ex.Message });
            }
            Serilog.Log.Information("User logged in successfully: {Email}", model.Email);
            return Ok(new { Token = accessToken, RefreshToken = refreshToken.Token, Expires = refreshToken.Expires, Id = loginUser.Id });
        }

        [HttpPost("refresh")]
        [AllowAnonymous]
        public async Task<IActionResult> Refresh([FromBody] RefreshTokenModel model)
        {
            Serilog.Log.Information("Refresh called: RefreshToken={RefreshToken}", model.RefreshToken);
            var existingRefreshToken = await _context.RefreshTokens
                .FirstOrDefaultAsync(t => t.Token == model.RefreshToken && !t.IsRevoked && t.Expires > DateTime.UtcNow);
            if (existingRefreshToken == null)
            {
                Serilog.Log.Warning("Invalid or expired refresh token: {RefreshToken}", model.RefreshToken);
                return Unauthorized(new { Message = "Invalid or expired refresh token" });
            }

            var refreshUser = await _userManager.FindByIdAsync(existingRefreshToken.UserId);
            if (refreshUser == null)
            {
                Serilog.Log.Error("User not found for refresh token: {RefreshToken}", model.RefreshToken);
                return Unauthorized(new { Message = "User not found" });
            }

            var newAccessToken = GenerateJwtToken(refreshUser);
            var newRefreshToken = GenerateRefreshToken(refreshUser.Id);
            existingRefreshToken.IsRevoked = true;
            _context.RefreshTokens.Add(newRefreshToken);
            try
            {
                await _context.SaveChangesAsync();
            }
            catch (DbUpdateException ex)
            {
                Serilog.Log.Error(ex, "Failed to update refresh token for user: {UserId}", refreshUser.Id);
                return StatusCode(500, new { Message = "Failed to update refresh token", Error = ex.Message });
            }
            Serilog.Log.Information("Token refreshed successfully for user: {Email}", refreshUser.Email);
            return Ok(new { AccessToken = newAccessToken, RefreshToken = newRefreshToken.Token, Expires = newRefreshToken.Expires });
        }

        [HttpPost("google-callback")]
        [AllowAnonymous]
        public async Task<IActionResult> GoogleCallback([FromBody] GoogleTokenModel model)
        {
            Serilog.Log.Information("Google callback called with ID token");
            if (string.IsNullOrEmpty(model.IdToken))
            {
                Serilog.Log.Error("No ID token provided");
                return BadRequest(new { Message = "No ID token provided" });
            }

            try
            {
                var clientId = _configuration["Google:ClientId"];
                if (string.IsNullOrEmpty(clientId))
                {
                    Serilog.Log.Error("Google ClientId is missing in configuration");
                    return StatusCode(500, new { Message = "Server configuration error: Missing Google ClientId" });
                }

                var settings = new GoogleJsonWebSignature.ValidationSettings
                {
                    Audience = new[] { clientId }
                };
                var payload = await GoogleJsonWebSignature.ValidateAsync(model.IdToken, settings);

                if (string.IsNullOrEmpty(payload.Email))
                {
                    Serilog.Log.Error("Email not provided in Google ID token");
                    return BadRequest(new { Message = "Email not provided in Google ID token" });
                }

                var googleUserEmail = payload.Email;
                var existingUser = await _userManager.FindByEmailAsync(googleUserEmail);

                if (existingUser == null)
                {
                    var newUser = new IdentityUser
                    {
                        UserName = googleUserEmail,
                        Email = googleUserEmail,
                        EmailConfirmed = true
                    };
                    var createResult = await _userManager.CreateAsync(newUser);
                    if (!createResult.Succeeded)
                    {
                        Serilog.Log.Error("Failed to create user: {Errors}", string.Join(", ", createResult.Errors.Select(e => e.Description)));
                        return BadRequest(new { Message = "Failed to create user", Errors = createResult.Errors });
                    }

                    var userLoginInfo = new UserLoginInfo("Google", payload.Subject, "Google");
                    var addLoginResult = await _userManager.AddLoginAsync(newUser, userLoginInfo);
                    if (!addLoginResult.Succeeded)
                    {
                        Serilog.Log.Error("Failed to add Google login: {Errors}", string.Join(", ", addLoginResult.Errors.Select(e => e.Description)));
                        return BadRequest(new { Message = "Failed to add Google login", Errors = addLoginResult.Errors });
                    }

                    await _userManager.AddToRoleAsync(newUser, "User");
                    var userProfile = new UserProfile
                    {
                        UserId = newUser.Id,
                        Username = googleUserEmail.Split('@')[0]
                    };
                    _context.UserProfiles.Add(userProfile);
                    try
                    {
                        await _context.SaveChangesAsync();
                    }
                    catch (DbUpdateException ex)
                    {
                        Serilog.Log.Error(ex, "Failed to save profile for user: {Email}", googleUserEmail);
                        return StatusCode(500, new { Message = "Failed to save profile", Error = ex.Message });
                    }
                    existingUser = newUser;
                }

                var accessToken = GenerateJwtToken(existingUser);
                var newRefreshToken = GenerateRefreshToken(existingUser.Id);
                _context.RefreshTokens.Add(newRefreshToken);
                try
                {
                    await _context.SaveChangesAsync();
                }
                catch (DbUpdateException ex)
                {
                    Serilog.Log.Error(ex, "Failed to save refresh token for user: {Email}", googleUserEmail);
                    return StatusCode(500, new { Message = "Failed to save refresh token", Error = ex.Message });
                }

                Serilog.Log.Information("Google login successful for user: {Email}", googleUserEmail);
                return Ok(new { Token = accessToken, RefreshToken = newRefreshToken.Token, Expires = newRefreshToken.Expires });
            }
            catch (InvalidJwtException ex)
            {
                Serilog.Log.Error(ex, "Invalid Google ID token");
                return BadRequest(new { Message = "Invalid Google ID token", Error = ex.Message });
            }
            catch (Exception ex)
            {
                Serilog.Log.Error(ex, "Unexpected error during Google login");
                return StatusCode(500, new { Message = "Unexpected error during Google login", Error = ex.Message });
            }
        }

        [HttpPost("logout")]
        [Authorize]
        public async Task<IActionResult> Logout([FromBody] RefreshTokenModel model)
        {
            Serilog.Log.Information("Logout called: RefreshToken={RefreshToken}", model.RefreshToken);
            var refreshToken = await _context.RefreshTokens
                .FirstOrDefaultAsync(t => t.Token == model.RefreshToken && !t.IsRevoked);
            if (refreshToken == null)
            {
                Serilog.Log.Warning("Invalid refresh token: {RefreshToken}", model.RefreshToken);
                return BadRequest(new { Message = "Invalid refresh token" });
            }

            refreshToken.IsRevoked = true;
            try
            {
                await _context.SaveChangesAsync();
            }
            catch (DbUpdateException ex)
            {
                Serilog.Log.Error(ex, "Failed to revoke refresh token: {RefreshToken}", model.RefreshToken);
                return StatusCode(500, new { Message = "Failed to revoke refresh token", Error = ex.Message });
            }

            Serilog.Log.Information("User logged out successfully");
            return Ok(new { Message = "Logged out successfully" });
        }

        [HttpPost("assign-role")]
        [Authorize(Roles = "Admin")]
        public async Task<IActionResult> AssignRole([FromBody] AssignRoleModel model)
        {
            var user = await _userManager.FindByEmailAsync(model.Email);
            if (user == null)
            {
                Serilog.Log.Error("User not found: {Email}", model.Email);
                return NotFound(new { Message = "User not found" });
            }

            var roleExists = await _roleManager.RoleExistsAsync(model.Role);
            if (!roleExists)
            {
                Serilog.Log.Error("Role not found: {Role}", model.Role);
                return NotFound(new { Message = "Role not found" });
            }

            if (await _userManager.IsInRoleAsync(user, model.Role))
            {
                Serilog.Log.Information("User {Email} already has role {Role}", model.Email, model.Role);
                return Ok(new { Message = "User already has this role" });
            }

            var result = await _userManager.AddToRoleAsync(user, model.Role);
            if (!result.Succeeded)
            {
                Serilog.Log.Error("Failed to assign role: {Errors}", string.Join(", ", result.Errors.Select(e => e.Description)));
                return BadRequest(new { Message = "Failed to assign role", Errors = result.Errors });
            }

            Serilog.Log.Information("Role {Role} assigned to user: {Email}", model.Role, model.Email);
            return Ok(new { Message = "Role assigned successfully" });
        }

        [Authorize(Roles = "Admin")]
        [HttpGet("admin")]
        public IActionResult AdminOnly()
        {
            Serilog.Log.Information("Admin endpoint called by user: {UserId}", User.FindFirst(ClaimTypes.NameIdentifier)?.Value);
            return Ok(new { Message = "Admin access granted" });
        }

        private async Task<string> GenerateJwtToken(IdentityUser user)
        {
            var claims = new[]
            {
            new Claim(JwtRegisteredClaimNames.Sub, user.Id), // Use user.Id, not Email
            new Claim(JwtRegisteredClaimNames.Email, user.Email),
            new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString()),
            new Claim(ClaimTypes.Name, user.UserName)
        };

            var key = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_configuration["Jwt:Key"]));
            var creds = new SigningCredentials(key, SecurityAlgorithms.HmacSha256);
            var expires = DateTime.UtcNow.AddDays(7);

            var token = new JwtSecurityToken(
                issuer: _configuration["Jwt:Issuer"],
                audience: _configuration["Jwt:Audience"],
                claims: claims,
                expires: expires,
                signingCredentials: creds
            );

            return new JwtSecurityTokenHandler().WriteToken(token);
        }



        private RefreshToken GenerateRefreshToken(string userId)
        {
            return new RefreshToken
            {
                UserId = userId,
                Token = Guid.NewGuid().ToString(),
                Expires = DateTime.UtcNow.AddDays(7),
                IsRevoked = false
            };
        }
    }
}