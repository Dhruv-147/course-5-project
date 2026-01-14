using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Logging;

namespace UserManagementApi.Middleware
{
    public class RequestLoggingMiddleware
    {
        private readonly RequestDelegate _next;
        private readonly ILogger<RequestLoggingMiddleware> _logger;

        public RequestLoggingMiddleware(RequestDelegate next, ILogger<RequestLoggingMiddleware> logger)
        {
            _next = next;
            _logger = logger;
        }

        public async Task Invoke(HttpContext context)
        {
            await _next(context);

            _logger.LogInformation(
                "HTTP {Method} {Path} responded {StatusCode}",
                context.Request.Method,
                context.Request.Path,
                context.Response.StatusCode);
        }
    }
}
