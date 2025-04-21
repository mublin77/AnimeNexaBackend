using AnimeApp.Core.Dtos;
using AnimeApp.Core.Services;
using CloudinaryDotNet;
using CloudinaryDotNet.Actions;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Identity;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Threading.Tasks;
using Microsoft.Extensions.Logging;

namespace AnimeApp.API.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class PostController : ControllerBase
    {
        private readonly IPostService _postService;
        private readonly Cloudinary _cloudinary;
        private readonly UserManager<IdentityUser> _userManager;
        private readonly ILogger<PostController> _logger;

        public PostController(
            IPostService postService,
            IConfiguration configuration,
            UserManager<IdentityUser> userManager,
            ILogger<PostController> logger)
        {
            _postService = postService;
            _userManager = userManager;
            _logger = logger;
            var cloudinaryAccount = new Account(
                configuration["Cloudinary:CloudName"],
                configuration["Cloudinary:ApiKey"],
                configuration["Cloudinary:ApiSecret"]);
            _cloudinary = new Cloudinary(cloudinaryAccount);
        }

        [HttpGet]
        public async Task<IActionResult> GetAllPosts()
        {
            try
            {
                var posts = await _postService.GetAllPostsAsync();
                _logger.LogInformation("Retrieved {PostCount} posts sorted by likes.", posts.Count);
                return Ok(posts);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to retrieve posts.");
                return StatusCode(500, new { message = "Failed to retrieve posts", error = ex.Message });
            }
        }

        [HttpPost]
        [Authorize]
        public async Task<IActionResult> CreatePost([FromForm] CreatePostDto model, IFormFile media)
        {
            if (!ModelState.IsValid || string.IsNullOrEmpty(model.Text))
            {
                _logger.LogWarning("Invalid model state or empty text in CreatePost.");
                return BadRequest(ModelState);
            }

            var userId = User.FindFirst(JwtRegisteredClaimNames.Sub)?.Value;
            if (string.IsNullOrEmpty(userId))
            {
                userId = User.FindFirst(ClaimTypes.NameIdentifier)?.Value;
                if (string.IsNullOrEmpty(userId))
                {
                    _logger.LogError("User not authenticated in CreatePost.");
                    return Unauthorized("User not authenticated.");
                }

                var userByEmail = await _userManager.FindByEmailAsync(userId);
                if (userByEmail != null)
                {
                    userId = userByEmail.Id;
                    _logger.LogWarning("Using email {Email} to resolve UserId {UserId} in CreatePost.", userId, userByEmail.Id);
                }
            }

            _logger.LogInformation("Attempting to create post for UserId: {UserId}", userId);

            var user = await _userManager.FindByIdAsync(userId);
            if (user == null)
            {
                _logger.LogError("User with UserId {UserId} not found in AspNetUsers.", userId);
                return BadRequest(new { message = "User not found in the system." });
            }

            string mediaUrl = null;
            string mediaType = null;

            if (media != null)
            {
                _logger.LogInformation("Uploading media for post by UserId: {UserId}", userId);
                var uploadParams = new RawUploadParams
                {
                    File = new FileDescription(media.FileName, media.OpenReadStream()),
                    Folder = "animeapp"
                };

                var uploadResult = await _cloudinary.UploadAsync(uploadParams);
                if (uploadResult.Error != null)
                {
                    _logger.LogError("Media upload failed for UserId {UserId}: {Error}", userId, uploadResult.Error.Message);
                    return BadRequest(new { message = "Media upload failed", error = uploadResult.Error.Message });
                }

                mediaUrl = uploadResult.SecureUrl.ToString();
                mediaType = media.ContentType.StartsWith("image") ? "image" : "video";
            }

            try
            {
                var post = await _postService.CreatePostAsync(userId, model, mediaUrl, mediaType);
                _logger.LogInformation("Post created successfully with Id: {PostId} for UserId: {UserId}", post.Id, userId);
                return Ok(new PostDto
                {
                    Id = post.Id,
                    UserId = post.UserId,
                    Username = post.User?.UserName ?? "Unknown",
                    Text = post.Text,
                    MediaUrl = post.MediaUrl,
                    MediaType = post.MediaType,
                    CreatedAt = post.CreatedAt,
                    UpdatedAt = post.UpdatedAt,
                    LikeCount = 0
                });
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to create post for UserId {UserId}.", userId);
                return StatusCode(500, new { message = "Failed to create post", error = ex.Message });
            }
        }

        [HttpGet("{id}")]
        public async Task<IActionResult> GetPost(string id)
        {
            var post = await _postService.GetPostByIdAsync(id);
            if (post == null)
            {
                _logger.LogWarning("Post with Id {PostId} not found.", id);
                return NotFound($"Post with ID {id} not found.");
            }
            return Ok(post);
        }

        [HttpPost("{id}/likes")]
        [Authorize]
        public async Task<IActionResult> LikePost(string id)
        {
            var userId = User.FindFirst(JwtRegisteredClaimNames.Sub)?.Value;
            if (string.IsNullOrEmpty(userId))
            {
                userId = User.FindFirst(ClaimTypes.NameIdentifier)?.Value;
                if (string.IsNullOrEmpty(userId))
                {
                    _logger.LogError("User not authenticated in LikePost.");
                    return Unauthorized("User not authenticated.");
                }

                var userByEmail = await _userManager.FindByEmailAsync(userId);
                if (userByEmail != null)
                    userId = userByEmail.Id;
            }

            try
            {
                await _postService.LikePostAsync(id, userId);
                _logger.LogInformation("Post {PostId} liked by UserId: {UserId}", id, userId);
                return Ok(new { message = "Post liked successfully" });
            }
            catch (InvalidOperationException ex) when (ex.Message == "User has already liked this post.")
            {
                _logger.LogInformation("User {UserId} attempted to like Post {PostId} again.", userId, id);
                return BadRequest(new { message = "You have already liked this post." });
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to like post {PostId} for UserId {UserId}.", id, userId);
                return StatusCode(500, new { message = "Failed to like post", error = ex.Message });
            }
        }

        [HttpPost("{id}/comments")]
        [Authorize]
        public async Task<IActionResult> CommentOnPost(string id, [FromBody] CommentModel model)
        {
            if (!ModelState.IsValid)
            {
                _logger.LogWarning("Invalid model state in CommentOnPost for PostId: {PostId}.", id);
                return BadRequest(ModelState);
            }

            var userId = User.FindFirst(JwtRegisteredClaimNames.Sub)?.Value;
            if (string.IsNullOrEmpty(userId))
            {
                userId = User.FindFirst(ClaimTypes.NameIdentifier)?.Value;
                if (string.IsNullOrEmpty(userId))
                {
                    _logger.LogError("User not authenticated in CommentOnPost.");
                    return Unauthorized("User not authenticated.");
                }

                var userByEmail = await _userManager.FindByEmailAsync(userId);
                if (userByEmail != null)
                    userId = userByEmail.Id;
            }

            try
            {
                await _postService.CommentOnPostAsync(id, userId, model.Content);
                _logger.LogInformation("Comment added to PostId: {PostId} by UserId: {UserId}", id, userId);
                return Ok(new { message = "Comment added successfully" });
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to comment on post {PostId} for UserId {UserId}.", id, userId);
                return StatusCode(500, new { message = "Failed to comment", error = ex.Message });
            }
        }

        [HttpPost("{id}/shares")]
        [Authorize]
        public async Task<IActionResult> SharePost(string id)
        {
            var userId = User.FindFirst(JwtRegisteredClaimNames.Sub)?.Value;
            if (string.IsNullOrEmpty(userId))
            {
                userId = User.FindFirst(ClaimTypes.NameIdentifier)?.Value;
                if (string.IsNullOrEmpty(userId))
                {
                    _logger.LogError("User not authenticated in SharePost.");
                    return Unauthorized("User not authenticated.");
                }

                var userByEmail = await _userManager.FindByEmailAsync(userId);
                if (userByEmail != null)
                    userId = userByEmail.Id;
            }

            try
            {
                await _postService.SharePostAsync(id, userId);
                _logger.LogInformation("Post {PostId} shared by UserId: {UserId}", id, userId);
                return Ok(new { message = "Post shared successfully" });
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to share post {PostId} for UserId {UserId}.", id, userId);
                return StatusCode(500, new { message = "Failed to share post", error = ex.Message });
            }
        }
    }

    public class CommentModel
    {
        public string Content { get; set; }
    }
}