// RepoLifecycleDetector.cs — flags repos created and deleted within 10 minutes

using GitHubSecurityMonitor.Models;

namespace GitHubSecurityMonitor.Detectors
{
    public class RepoLifecycleDetector : Detector
    {
        private readonly Dictionary<string, long> _repoCreationTimes = new();

        protected override bool CanHandle(string eventType)
        {
            return eventType == "repository";
        }

        protected override Alert? Detect(GitHubEvent gitHubEvent)
        {
            var repoName = gitHubEvent.Payload.GetProperty("repository").GetProperty("name").GetString();
            var action = gitHubEvent.Payload.GetProperty("action").GetString();

            if (repoName == null || action == null) return null;

            if (action == "created")
            {
                _repoCreationTimes[repoName] = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds();
            }

            if (action == "deleted")
            {
                // fallback to GitHub payload if created event was missed
                long createdAt;
                if (_repoCreationTimes.TryGetValue(repoName, out long storedTime))
                {
                    createdAt = storedTime;
                }
                else
                {
                    var createdAtString = gitHubEvent.Payload
                        .GetProperty("repository")
                        .GetProperty("created_at")
                        .GetString();
                    if (createdAtString == null) return null;
                    createdAt = DateTimeOffset.Parse(createdAtString).ToUnixTimeMilliseconds();
                }

                _repoCreationTimes.Remove(repoName);

                var elapsed = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds() - createdAt;
                if (elapsed < 600000)
                {
                    return new Alert
                    {
                        EventType = gitHubEvent.Type,
                        Description = "Repository deleted within 10 minutes of creation",
                        DetectedAt = DateTime.UtcNow.ToString("o"),
                        Payload = gitHubEvent.Payload
                    };
                }
            }
            return null;
        }
    }
}