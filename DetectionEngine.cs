// DetectionEngine.cs — orchestrates detectors and notifiers

using GitHubSecurityMonitor.Models;
using GitHubSecurityMonitor.Detectors;
using GitHubSecurityMonitor.Notifiers;

namespace GitHubSecurityMonitor
{
    public class DetectionEngine
    {
        private readonly List<Detector> _detectors;
        private readonly List<INotifier> _notifiers;
        private readonly TimeSpan _timeout = TimeSpan.FromSeconds(5);

        public DetectionEngine(List<Detector> detectors, List<INotifier> notifiers)
        {
            _detectors = detectors;
            _notifiers = notifiers;
        }

        public async Task ProcessAsync(GitHubEvent gitHubEvent)
        {
            foreach (var detector in _detectors)
            {
                if (!detector.SafeCanHandle(gitHubEvent.Type)) continue;

                try
                {
                    using var cts = new CancellationTokenSource(_timeout);
                    var alert = await Task.Run(() => detector.SafeDetect(gitHubEvent), cts.Token);

                    if (alert != null)
                    {
                        foreach (var notifier in _notifiers)
                        {
                            try
                            {
                                notifier.Notify(alert);
                            }
                            catch (Exception ex)
                            {
                                Console.Error.WriteLine($"{notifier.GetType().Name} failed: {ex.Message}");
                            }
                        }
                    }
                }
                catch (OperationCanceledException)
                {
                    Console.Error.WriteLine($"{detector.GetType().Name} timed out after {_timeout.TotalSeconds}s");
                }
                catch (Exception ex)
                {
                    Console.Error.WriteLine($"{detector.GetType().Name} failed: {ex.Message}");
                }
            }
        }
    }
}