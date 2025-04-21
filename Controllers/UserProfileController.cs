using AnimeApp.Core.Dtos;
using AnimeApp.Core.Models;
using AnimeApp.Core.Services;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using System.Security.Claims;
using System.Threading.Tasks;

namespace AnimeApp.API.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class UserProfileController : ControllerBase
    {
        private readonly IUserProfileService _profileService;

        public UserProfileController(IUserProfileService profileService)
        {
            _profileService = profileService;
        }

        [HttpGet("{id}")]
        public async Task<IActionResult> GetProfile(string id)
        {
            var profile = await _profileService.GetProfileByIdAsync(id);
            if (profile == null)
            {
                return NotFound($"Profile with ID {id} not found.");
            }

            var profileDto = new UserProfileDto
            {
                Id = profile.Id,
                UserId = profile.UserId,
                Username = profile.Username,
                Bio = profile.Bio,
                ProfilePhotoUrl = profile.ProfilePhotoUrl,
                Links = profile.Links,
                CreatedAt = profile.CreatedAt,
                Email = profile.User.Email,
                UpdatedAt = profile.UpdatedAt
            };

            return Ok(profileDto);
        }

        [HttpPut("{id}")]
        [Authorize]
        public async Task<IActionResult> UpdateProfile(string id, [FromBody] UpdateUserProfileDto model)
        {
            if (!ModelState.IsValid)
            {
                return BadRequest(ModelState);
            }

            var userId = User.FindFirst(ClaimTypes.NameIdentifier)?.Value;
            
            if (string.IsNullOrEmpty(userId))
            {
                return Unauthorized("User not authenticated.");
            }

            var profile = await _profileService.GetProfileByIdAsync(id);
            Console.WriteLine(profile.UserId);
            Console.WriteLine(userId);

            if (profile == null)
            {
                return NotFound($"Profile with ID {id} not found.");
            }

            if (profile.UserId != userId && !User.IsInRole("ADMIN"))
            {
                return Forbid("You can only update your own profile.");
            }

            // Update only provided fields
            profile.Username = model.Username ?? profile.Username;
            profile.Bio = model.Bio ?? profile.Bio;
            profile.ProfilePhotoUrl = model.ProfilePhotoUrl ?? profile.ProfilePhotoUrl;
            profile.Links = model.Links ?? profile.Links;
            profile.UpdatedAt = DateTime.UtcNow;

            var updatedProfile = await _profileService.UpdateProfileAsync(profile);

            var updatedProfileDto = new UserProfileDto
            {
                Id = updatedProfile.Id,
                UserId = updatedProfile.UserId,
                Username = updatedProfile.Username,
                Bio = updatedProfile.Bio,
                ProfilePhotoUrl = updatedProfile.ProfilePhotoUrl,
                Links = updatedProfile.Links,
                CreatedAt = updatedProfile.CreatedAt,
                UpdatedAt = updatedProfile.UpdatedAt,
                Email = updatedProfile.User.Email
            };

            return Ok(updatedProfileDto);
        }
    }
}