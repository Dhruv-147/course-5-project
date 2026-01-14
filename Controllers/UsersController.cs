using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using UserManagementApi.Data;
using UserManagementApi.Models;

namespace UserManagementApi.Controllers
{
    [ApiController]
    [Route("api/[controller]")]
    public class UsersController : ControllerBase
    {
        private readonly UserDbContext _context;

        public UsersController(UserDbContext context)
        {
            _context = context;
        }

        // GET: api/users?page=1&pageSize=10
        [HttpGet]
        public async Task<ActionResult<IEnumerable<User>>> GetUsers(int page = 1, int pageSize = 10)
        {
            try
            {
                return await _context.Users
                    .AsNoTracking()
                    .Skip((page - 1) * pageSize)
                    .Take(pageSize)
                    .ToListAsync();
            }
            catch
            {
                return StatusCode(500, "Error retrieving users");
            }
        }

        // GET: api/users/5
        [HttpGet("{id}")]
        public async Task<ActionResult<User>> GetUser(int id)
        {
            try
            {
                var user = await _context.Users.AsNoTracking().FirstOrDefaultAsync(u => u.Id == id);
                if (user == null) return NotFound("User not found");
                return user;
            }
            catch
            {
                return StatusCode(500, "Error retrieving user");
            }
        }

        // POST: api/users
        [HttpPost]
        public async Task<ActionResult<User>> CreateUser(User user)
        {
            if (!ModelState.IsValid)
                return BadRequest(ModelState);

            try
            {
                _context.Users.Add(user);
                await _context.SaveChangesAsync();
                return CreatedAtAction(nameof(GetUser), new { id = user.Id }, user);
            }
            catch (DbUpdateException)
            {
                return Conflict("Email already exists");
            }
            catch
            {
                return StatusCode(500, "Error creating user");
            }
        }

        // PUT: api/users/5
        [HttpPut("{id}")]
        public async Task<IActionResult> UpdateUser(int id, User updatedUser)
        {
            if (!ModelState.IsValid)
                return BadRequest(ModelState);

            try
            {
                var user = await _context.Users.FindAsync(id);
                if (user == null) return NotFound("User not found");

                user.Name = updatedUser.Name;
                user.Email = updatedUser.Email;

                await _context.SaveChangesAsync();
                return NoContent();
            }
            catch (DbUpdateException)
            {
                return Conflict("Email already exists");
            }
            catch
            {
                return StatusCode(500, "Error updating user");
            }
        }

        // DELETE: api/users/5
        [HttpDelete("{id}")]
        public async Task<IActionResult> DeleteUser(int id)
        {
            try
            {
                var user = await _context.Users.FindAsync(id);
                if (user == null) return NotFound("User not found");

                _context.Users.Remove(user);
                await _context.SaveChangesAsync();
                return NoContent();
            }
            catch
            {
                return StatusCode(500, "Error deleting user");
            }
        }
    }
}
