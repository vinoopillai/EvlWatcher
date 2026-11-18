using System;
using System.Collections.Generic;
using System.Linq;
using EvlWatcher.WCF.DTO;

namespace EvlWatcher.Config
{
    /// <summary>
    /// Maps between persisted task configurations and the WCF rule DTO.
    /// </summary>
    internal static class RuleMapper
    {
        internal static GenericIPBlockingTaskDTO ToDto(IPersistentTaskConfiguration c, Func<string, bool> eventLogExists)
        {
            var paths = (c.EventPath ?? string.Empty)
                .Split(',')
                .Select(p => p.Trim())
                .Where(p => p.Length > 0)
                .ToList();

            return new GenericIPBlockingTaskDTO
            {
                Active = c.Active,
                TaskName = c.TaskName,
                Description = c.Description,
                LockTime = c.LockTime,
                OnlyNewEvents = c.OnlyNewEvents,
                EventAge = c.EventAge,
                TriggerCount = c.TriggerCount,
                PermaBanCount = c.PermaBanCount,
                EventPath = paths,
                MissingEventLogs = paths.Where(p => !eventLogExists(p)).ToList(),
                RegexBoosters = c.RegexBoosters.ToList(),
                Regex = c.Regex
            };
        }

        /// <summary>
        /// Copies every field except TaskName onto the target.
        /// </summary>
        internal static void Apply(GenericIPBlockingTaskDTO dto, IPersistentTaskConfiguration target)
        {
            target.Description = dto.Description;
            target.LockTime = dto.LockTime;
            target.OnlyNewEvents = dto.OnlyNewEvents;
            target.EventAge = dto.EventAge;
            target.TriggerCount = dto.TriggerCount;
            target.PermaBanCount = dto.PermaBanCount;
            target.EventPath = string.Join(",", (dto.EventPath ?? new List<string>()).Select(p => p.Trim()));
            target.Regex = dto.Regex;
            target.SetRegexBoosters(dto.RegexBoosters ?? new List<string>());
            // Active goes last: a rule that fails midway must never end up enabled but half-written.
            target.Active = dto.Active;
        }
    }
}
