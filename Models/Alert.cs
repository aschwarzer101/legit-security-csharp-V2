// Alert.cs - shared Alert type used across application 
using System.Text.Json;

namespace GitHubSecurityMonitor.Models
{
    public class Alert
    {
        public string EventType { get; set; } = string.Empty;
        public string Description { get; set; } = string.Empty;
        public string DetectedAt { get; set; } = string.Empty;
        public JsonElement Payload { get; set; }
    }
}