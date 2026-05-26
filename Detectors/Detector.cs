// Detector.cs — abstract base class for all detectors

using GitHubSecurityMonitor.Models;

namespace GitHubSecurityMonitor.Detectors
{
    public abstract class Detector
    {
        // safe public wrappers; what DetectionEngine calls
        public bool SafeCanHandle(string eventType)
        {
            try
            {
                return CanHandle(eventType);
            }
            catch (Exception ex)
            {
                Console.Error.WriteLine($"{GetType().Name}.CanHandle failed: {ex.Message}");
                return false;
            }
        }

        public Alert? SafeDetect(GitHubEvent gitHubEvent)
        {
            try
            {
                return Detect(gitHubEvent);
            }
            catch (Exception ex)
            {
                Console.Error.WriteLine($"{GetType().Name}.Detect failed: {ex.Message}");
                return null;
            }
        }

        // protected — subclasses implement these, can't be called directly from outside
        protected abstract bool CanHandle(string eventType);
        protected abstract Alert? Detect(GitHubEvent gitHubEvent);
    }
}