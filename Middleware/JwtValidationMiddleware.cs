using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Text;

namespace UserManagementApi.Middleware
{
    public class JwtValidationMiddleware
    {
        private readonly RequestDelegate _next;
        private readonly IConfiguration _config;

        public JwtValidationMiddleware(RequestDelegate next, IConfiguration config)
        {
            _next = next;
            _config = config;
        }

        public async Task Invoke(HttpContext context)
        {
            // Skip token validation for auth endpoints
            if (context.Request.Path.StartsWithSegments("/api/auth"))
            {
                await _next(context);
                return;
            }

            var token = context.Request.Headers["Authorization"]
                .FirstOrDefault()?.Split(" ").Last();


            if (string.IsNullOrEmpty(token))
            {
                context.Response.StatusCode = 401;
                await context.Response.WriteAsJsonAsync(new { error = "Missing token" });
                return;
            }

            try
            {
                var key = Encoding.UTF8.GetBytes(_config["Jwt:Key"]!);

                var tokenHandler = new JwtSecurityTokenHandler();
                tokenHandler.ValidateToken(token, new TokenValidationParameters
                {
                    ValidateIssuer = true,
                    ValidateAudience = true,
                    ValidateLifetime = true,
                    ValidateIssuerSigningKey = true,
                    ValidIssuer = _config["Jwt:Issuer"],
                    ValidAudience = _config["Jwt:Audience"],
                    IssuerSigningKey = new SymmetricSecurityKey(key)
                }, out _);

                await _next(context);
            }
            catch
            {
                context.Response.StatusCode = 401;
                await context.Response.WriteAsJsonAsync(new { error = "Invalid token" });
            }
        }
    }
}
