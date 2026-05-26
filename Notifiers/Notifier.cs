// Notifier.cs — interface for all notification methods

using GitHubSecurityMonitor.Models;

namespace GitHubSecurityMonitor.Notifiers
{
    public interface INotifier
    {
        void Notify(Alert alert);
    }
}