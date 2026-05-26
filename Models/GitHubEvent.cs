// GitHubEvent.cs - shared github event type used across application 

using System.Text.Json;

namespace GitHubSecurityMonitor.Models
{
    public class GitHubEvent
    {
        public string Type { get; set; } = string.Empty;
        public JsonElement Payload { get; set; }
    }
}