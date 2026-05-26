// SuspiciousHoursDetector.cs — flags push events between 14:00 and 16:00
// uses committer's local timezone from GitHub payload rather than server time

using GitHubSecurityMonitor.Models;

namespace GitHubSecurityMonitor.Detectors
{
    public class SuspiciousHoursDetector : Detector
    {
        protected override bool CanHandle(string eventType)
        {
            return eventType == "push";
        }

        protected override Alert? Detect(GitHubEvent gitHubEvent)
        {
            // gets time from event payload rather than local device 
            var timestamp = gitHubEvent.Payload
                .GetProperty("head_commit")
                .GetProperty("timestamp")
                .GetString();

            if (timestamp == null) return null;

            // preserves timesone offset from GitHubt timestamp string
            var commitTime = DateTimeOffset.Parse(timestamp);
            var hour = commitTime.Hour;

            if (hour >= 14 && hour < 16)
            {
                return new Alert
                {
                    EventType = gitHubEvent.Type,
                    Description = "Suspicious push detected during restricted hours (14:00-16:00)",
                    DetectedAt = DateTime.UtcNow.ToString("o"),
                    Payload = gitHubEvent.Payload
                };
            }
            return null;
        }
    }
}