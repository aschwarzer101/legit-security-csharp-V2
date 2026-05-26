// ConsoleNotifier.cs — prints alerts to console

using GitHubSecurityMonitor.Models;

namespace GitHubSecurityMonitor.Notifiers
{
    public class ConsoleNotifier : INotifier
    {
        public void Notify(Alert alert)
        {
            Console.WriteLine($"""
                SUSPICIOUS ACTIVITY DETECTED
                Event:       {alert.EventType}
                Description: {alert.Description}
                Detected At: {alert.DetectedAt}
                Payload:     {alert.Payload}
                """);
        }
    }
}