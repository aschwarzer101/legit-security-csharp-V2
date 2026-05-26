// Program.cs — entry point and webhook server

using GitHubSecurityMonitor.Detectors;
using GitHubSecurityMonitor.Notifiers;
using GitHubSecurityMonitor;
using System.Text.Json;

var builder = WebApplication.CreateBuilder(args);
var app = builder.Build();

// wire up detectors and notifiers
var detectionEngine = new DetectionEngine(
    new List<Detector>
    {
        new SuspiciousHoursDetector(),
        new HackerTeamDetector(),
        new RepoLifecycleDetector()
    },
    new List<INotifier>
    {
        new ConsoleNotifier()
    }
);

// webhook endpoint
app.MapPost("/webhook", async (HttpContext context) =>
{
    var eventType = context.Request.Headers["X-GitHub-Event"].ToString();
    var payload = await JsonDocument.ParseAsync(context.Request.Body);

    var gitHubEvent = new GitHubSecurityMonitor.Models.GitHubEvent
    {
        Type = eventType,
        Payload = payload.RootElement
    };

    await detectionEngine.ProcessAsync(gitHubEvent);

    return Results.Ok("OK");
});

app.Run();