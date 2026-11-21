using EvlWatcher.Config;
using EvlWatcher.Geo;
using EvlWatcher.Logging;

namespace EvlWatcher.Tasks
{
    class DefaultGenericTaskFactory : IGenericTaskFactory
    {
        private readonly ILogger _logger;
        private readonly ICountryLookup _countries;

        public DefaultGenericTaskFactory(ILogger logger)
            : this(logger, CountryDatabase.Empty)
        {
        }

        public DefaultGenericTaskFactory(ILogger logger, ICountryLookup countries)
        {
            _logger = logger;
            _countries = countries ?? CountryDatabase.Empty;
        }

        public IPBlockingLogTask CreateFromConfiguration(IPersistentTaskConfiguration config)
        {
            return GenericIPBlockingTask.FromConfiguration(config, _logger, _countries);
        }
    }
}
