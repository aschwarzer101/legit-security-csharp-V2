
// Hacker Team Detector - flags if team is created under org. that starts with "hacker"

using GitHubSecurityMonitor.Models;

namespace GitHubSecurityMonitor.Detectors
{
    public class HackerTeamDetector : Detector
    {
        protected override bool CanHandle(string eventType)
        {
            return eventType == "team";
        }

        protected override Alert? Detect(GitHubEvent gitHubEvent)
        {
            var action = gitHubEvent.Payload.GetProperty("action").GetString();
            var teamName = gitHubEvent.Payload.GetProperty("team").GetProperty("name").GetString();

            if (action == "created" && teamName != null && teamName.StartsWith("hacker"))
            {
                    return new Alert{
                        EventType = gitHubEvent.Type,
                        Description = "Team created with hacker prefix",
                        DetectedAt = DateTime.UtcNow.ToString("o"),
                        Payload = gitHubEvent.Payload
                    };
            }
            return null; 
        }
    }
}