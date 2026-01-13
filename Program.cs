using Microsoft.AspNetCore.Builder;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using System.ComponentModel.DataAnnotations;
using System.Diagnostics;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Logging;
using System.Threading.Tasks;
using System.Net;
using System.Text.Json;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;
using Microsoft.IdentityModel.Tokens;

var builder = WebApplication.CreateBuilder(args);

var issuer = builder.Configuration["Jwt:Issuer"] ?? "your-issuer";
var audience = builder.Configuration["Jwt:Audience"] ?? "your-audience";
var secret = builder.Configuration["Jwt:Secret"] ?? "super-secret-key-change-me";

builder.Services.AddTokenValidation(issuer, audience, secret);


// Configure services
builder.Services.AddEndpointsApiExplorer();
builder.Services.AddSwaggerGen();


// Use SQLite for persistence (change to SQL Server/Postgres as needed)
var connectionString = builder.Configuration.GetConnectionString("DefaultConnection")
                      ?? "Data Source=users.db";
builder.Services.AddDbContext<AppDbContext>(options =>
    options.UseSqlite(connectionString));

// Allow simple CORS for local testing (adjust origins for production)
builder.Services.AddCors(options =>
{
    options.AddDefaultPolicy(policy =>
        policy.AllowAnyOrigin().AllowAnyHeader().AllowAnyMethod());
});

var app = builder.Build();

// Ensure database is created
using (var scope = app.Services.CreateScope())
{
    var db = scope.ServiceProvider.GetRequiredService<AppDbContext>();
    db.Database.EnsureCreated();
}

// Middleware
if (app.Environment.IsDevelopment())
{
    app.UseSwagger();
    app.UseSwaggerUI();
}

app.UseCors();
app.UseCustomExceptionHandler();
app.UseWhen(context =>
       !context.Request.Path.StartsWithSegments("/swagger") &&
       !context.Request.Path.StartsWithSegments("/swagger/index.html") &&
       !context.Request.Path.StartsWithSegments("/swagger/v1/swagger.json") &&
       // exclude auth endpoints (so you can request a token without being validated)
       !context.Request.Path.StartsWithSegments("/auth"),
    appBuilder =>
    {
        appBuilder.UseTokenValidation(); // your custom middleware
    });
app.UseRequestLogging();
app.UseHttpsRedirection();

if (app.Environment.IsDevelopment())
{
    app.UseSwagger();
    app.UseSwaggerUI();
}

// Minimal API endpoints for User CRUD


// GET /users? page, limit, q (search by name or email), department
app.MapGet("/users", async (AppDbContext db, int page = 1, int limit = 20, string? q = null, string? department = null) =>
{
    page = Math.Max(page, 1);
    limit = Math.Clamp(limit, 1, 100);
    var query = db.Users.AsQueryable();

    if (!string.IsNullOrWhiteSpace(q))
    {
        q = q.Trim();
        query = query.Where(u =>
            EF.Functions.Like(u.FirstName, $"%{q}%") ||
            EF.Functions.Like(u.LastName, $"%{q}%") ||
            EF.Functions.Like(u.Email, $"%{q}%"));
    }

    if (!string.IsNullOrWhiteSpace(department))
    {
        query = query.Where(u => u.Department == department);
    }

    var total = await query.CountAsync();
    var items = await query
        .OrderByDescending(u => u.CreatedAt)
        .Skip((page - 1) * limit)
        .Take(limit)
        .ToListAsync();

    return Results.Ok(new
    {
        meta = new { total, page, limit, pages = (int)Math.Ceiling(total / (double)limit) },
        data = items
    });
});

// GET /users/{id}
app.MapGet("/users/{id:int}", async (AppDbContext db, int id) =>
{
    var user = await db.Users.FindAsync(id);
    return user is not null ? Results.Ok(user) : Results.NotFound(new { error = "User not found" });
});

// POST /users
app.MapPost("/users", async (AppDbContext db, CreateUserDto dto) =>
{
    // Basic validation
    var validationErrors = dto.Validate();
    if (validationErrors.Any())
        return Results.BadRequest(new { errors = validationErrors });

    // Check unique email
    var exists = await db.Users.AnyAsync(u => u.Email == dto.Email);
    if (exists)
        return Results.Conflict(new { error = "Email already exists" });

    var user = new User
    {
        FirstName = dto.FirstName!,
        LastName = dto.LastName!,
        Email = dto.Email!,
        JobTitle = dto.JobTitle,
        Department = dto.Department,
        Phone = dto.Phone,
        CreatedAt = DateTime.UtcNow,
        UpdatedAt = DateTime.UtcNow
    };

    db.Users.Add(user);
    await db.SaveChangesAsync();

    return Results.Created($"/users/{user.Id}", user);
});

// PUT /users/{id}
app.MapPut("/users/{id:int}", async (AppDbContext db, int id, UpdateUserDto dto) =>
{
    var user = await db.Users.FindAsync(id);
    if (user is null) return Results.NotFound(new { error = "User not found" });

    var validationErrors = dto.Validate();
    if (validationErrors.Any())
        return Results.BadRequest(new { errors = validationErrors });

    if (!string.IsNullOrWhiteSpace(dto.Email) && dto.Email != user.Email)
    {
        var emailTaken = await db.Users.AnyAsync(u => u.Email == dto.Email && u.Id != id);
        if (emailTaken) return Results.Conflict(new { error = "Email already exists" });
        user.Email = dto.Email;
    }

    if (!string.IsNullOrWhiteSpace(dto.FirstName)) user.FirstName = dto.FirstName;
    if (!string.IsNullOrWhiteSpace(dto.LastName)) user.LastName = dto.LastName;
    if (dto.JobTitle is not null) user.JobTitle = dto.JobTitle;
    if (dto.Department is not null) user.Department = dto.Department;
    if (dto.Phone is not null) user.Phone = dto.Phone;

    user.UpdatedAt = DateTime.UtcNow;

    await db.SaveChangesAsync();
    return Results.Ok(user);
});

// DELETE /users/{id}
app.MapDelete("/users/{id:int}", async (AppDbContext db, int id) =>
{
    var user = await db.Users.FindAsync(id);
    if (user is null) return Results.NotFound(new { error = "User not found" });

    db.Users.Remove(user);
    await db.SaveChangesAsync();
    return Results.NoContent();
});

app.Run();

#region Supporting types (can be moved to separate files)

// Simple EF Core DbContext and User entity. Move to separate files in a real project.
public class AppDbContext : DbContext
{
    public AppDbContext(DbContextOptions<AppDbContext> options) : base(options) { }

    public DbSet<User> Users => Set<User>();

    protected override void OnModelCreating(ModelBuilder modelBuilder)
    {
        modelBuilder.Entity<User>()
            .HasIndex(u => u.Email)
            .IsUnique();

        base.OnModelCreating(modelBuilder);
    }
}

public class User
{
    public int Id { get; set; }

    [Required, MaxLength(100)]
    public string? FirstName { get; set; }

    [Required, MaxLength(100)]
    public string? LastName { get; set; }

    [Required, MaxLength(256), EmailAddress]
    public string? Email { get; set; }

    [MaxLength(100)]
    public string? JobTitle { get; set; }

    [MaxLength(100)]
    public string? Department { get; set; }

    [MaxLength(30)]
    public string? Phone { get; set; }

    public DateTime CreatedAt { get; set; }
    public DateTime UpdatedAt { get; set; }
}

// DTOs for create/update with simple validation helpers
public record CreateUserDto
{
    public string? FirstName { get; init; }
    public string? LastName { get; init; }
    public string? Email { get; init; }
    public string? JobTitle { get; init; }
    public string? Department { get; init; }
    public string? Phone { get; init; }

    public List<string> Validate()
    {
        var errors = new List<string>();
        if (string.IsNullOrWhiteSpace(FirstName)) errors.Add("FirstName is required.");
        if (string.IsNullOrWhiteSpace(LastName)) errors.Add("LastName is required.");
        if (string.IsNullOrWhiteSpace(Email)) errors.Add("Email is required.");
        else if (!new EmailAddressAttribute().IsValid(Email)) errors.Add("Email is not valid.");
        return errors;
    }
}

public record UpdateUserDto
{
    public string? FirstName { get; init; }
    public string? LastName { get; init; }
    public string? Email { get; init; }
    public string? JobTitle { get; init; }
    public string? Department { get; init; }
    public string? Phone { get; init; }

    public List<string> Validate()
    {
        var errors = new List<string>();
        if (!string.IsNullOrWhiteSpace(Email) && !new EmailAddressAttribute().IsValid(Email))
            errors.Add("Email is not valid.");
        return errors;
    }
}

public class RequestLoggingMiddleware
{
    private readonly RequestDelegate _next;
    private readonly ILogger<RequestLoggingMiddleware> _logger;

    public RequestLoggingMiddleware(RequestDelegate next, ILogger<RequestLoggingMiddleware> logger)
    {
        _next = next;
        _logger = logger;
    }

    public async Task InvokeAsync(HttpContext context)
    {
        var sw = Stopwatch.StartNew();
        try
        {
            await _next(context);
        }
        catch (Exception ex)
        {
            // Log exception with request context then rethrow so other middleware/handlers can handle it
            _logger.LogError(ex, "Unhandled exception while processing HTTP {Method} {Path}", 
                context.Request.Method, context.Request.Path);
            throw;
        }
        finally
        {
            sw.Stop();
            var statusCode = context.Response?.StatusCode;
            _logger.LogInformation("HTTP {Method} {Path} responded {StatusCode} in {ElapsedMs}ms",
                context.Request.Method,
                context.Request.Path,
                statusCode,
                sw.ElapsedMilliseconds);
        }
    }
}

public static class RequestLoggingMiddlewareExtensions
{
    public static IApplicationBuilder UseRequestLogging(this IApplicationBuilder app)
    {
        return app.UseMiddleware<RequestLoggingMiddleware>();
    }
}

public class ExceptionHandlingMiddleware
{
    private readonly RequestDelegate _next;
    private readonly ILogger<ExceptionHandlingMiddleware> _logger;

    public ExceptionHandlingMiddleware(RequestDelegate next, ILogger<ExceptionHandlingMiddleware> logger)
    {
        _next = next;
        _logger = logger;
    }

    public async Task InvokeAsync(HttpContext context)
    {
        try
        {
            await _next(context);
        }
        catch (DbUpdateConcurrencyException ex)
        {
            _logger.LogWarning(ex, "Concurrency conflict for {Method} {Path}", context.Request.Method, context.Request.Path);
            await WriteJsonResponse(context, HttpStatusCode.Conflict, new { error = "Concurrency conflict." });
        }
        catch (DbUpdateException ex)
        {
            _logger.LogError(ex, "Database update failed for {Method} {Path}", context.Request.Method, context.Request.Path);
            await WriteJsonResponse(context, HttpStatusCode.BadRequest, new { error = "Database update failed." });
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Unhandled exception for {Method} {Path}", context.Request.Method, context.Request.Path);
            await WriteJsonResponse(context, HttpStatusCode.InternalServerError, new { error = "Internal server error." });
        }
    }

    private static async Task WriteJsonResponse(HttpContext context, HttpStatusCode statusCode, object payload)
    {
        context.Response.Clear();
        context.Response.StatusCode = (int)statusCode;
        context.Response.ContentType = "application/json";
        var options = new JsonSerializerOptions { PropertyNamingPolicy = JsonNamingPolicy.CamelCase };
        await context.Response.WriteAsync(JsonSerializer.Serialize(payload, options));
    }
}

public static class ExceptionHandlingMiddlewareExtensions
{
    public static IApplicationBuilder UseCustomExceptionHandler(this IApplicationBuilder app)
    {
        return app.UseMiddleware<ExceptionHandlingMiddleware>();
    }
}

public class TokenValidationMiddleware
{
    private readonly RequestDelegate _next;
    private readonly ILogger<TokenValidationMiddleware> _logger;
    private readonly TokenValidationParameters _validationParameters;

    public TokenValidationMiddleware(RequestDelegate next, ILogger<TokenValidationMiddleware> logger, TokenValidationParameters validationParameters)
    {
        _next = next;
        _logger = logger;
        _validationParameters = validationParameters;
    }

    public async Task InvokeAsync(HttpContext context)
    {
        // Allow anonymous for OPTIONS and health checks
        if (HttpMethods.IsOptions(context.Request.Method))
        {
            await _next(context);
            return;
        }

        var authHeader = context.Request.Headers["Authorization"].FirstOrDefault();
        if (string.IsNullOrWhiteSpace(authHeader) || !authHeader.StartsWith("Bearer ", StringComparison.OrdinalIgnoreCase))
        {
            context.Response.StatusCode = StatusCodes.Status401Unauthorized;
            await context.Response.WriteAsJsonAsync(new { error = "Unauthorized" });
            return;
        }

        var token = authHeader.Substring("Bearer ".Length).Trim();
        var handler = new JwtSecurityTokenHandler();

        try
        {
            // Validate token and set principal
            var principal = handler.ValidateToken(token, _validationParameters, out var validatedToken);

            // Optional: additional checks (e.g., token alg)
            if (validatedToken is JwtSecurityToken jwt && !jwt.Header.Alg.Equals(SecurityAlgorithms.HmacSha256, StringComparison.OrdinalIgnoreCase))
            {
                _logger.LogWarning("Unexpected token algorithm: {Alg}", jwt.Header.Alg);
                context.Response.StatusCode = StatusCodes.Status401Unauthorized;
                await context.Response.WriteAsJsonAsync(new { error = "Unauthorized" });
                return;
            }

            context.User = principal;
            await _next(context);
        }
        catch (SecurityTokenExpiredException ex)
        {
            _logger.LogInformation(ex, "Token expired for {Path}", context.Request.Path);
            context.Response.StatusCode = StatusCodes.Status401Unauthorized;
            await context.Response.WriteAsJsonAsync(new { error = "Token expired" });
        }
        catch (SecurityTokenException ex)
        {
            _logger.LogInformation(ex, "Token validation failed for {Path}", context.Request.Path);
            context.Response.StatusCode = StatusCodes.Status401Unauthorized;
            await context.Response.WriteAsJsonAsync(new { error = "Unauthorized" });
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Unexpected error validating token for {Path}", context.Request.Path);
            context.Response.StatusCode = StatusCodes.Status500InternalServerError;
            await context.Response.WriteAsJsonAsync(new { error = "Internal server error." });
        }
    }
}

public static class TokenValidationExtensions
{
    public static IApplicationBuilder UseTokenValidation(this IApplicationBuilder app)
    {
        // Resolve TokenValidationParameters from DI
        var validationParameters = app.ApplicationServices.GetRequiredService<TokenValidationParameters>();
        return app.UseMiddleware<TokenValidationMiddleware>(validationParameters);
    }

    public static IServiceCollection AddTokenValidation(this IServiceCollection services, string issuer, string audience, string secretKey)
    {
        var key = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(secretKey));

        var validationParameters = new TokenValidationParameters
        {
            ValidateIssuer = !string.IsNullOrWhiteSpace(issuer),
            ValidIssuer = issuer,
            ValidateAudience = !string.IsNullOrWhiteSpace(audience),
            ValidAudience = audience,
            ValidateIssuerSigningKey = true,
            IssuerSigningKey = key,
            ValidateLifetime = true,
            ClockSkew = TimeSpan.FromSeconds(30)
        };

        services.AddSingleton(validationParameters);
        return services;
    }
}

#endregion