using System;
using System.IO;
using System.Text.Json;
using System.Threading.Tasks;

namespace SimpleFirewall.Core
{
    public class SimpleLogger
    {
        private readonly string _logFilePath;
        private readonly object _lock = new object();

        public SimpleLogger(string logFilePath = "firewall_events.jsonl")
        {
            _logFilePath = logFilePath;
        }

        public void LogBlock(PacketInfo packet, string ruleId)
        {
            var logEntry = new
            {
                Timestamp = packet.Timestamp.ToString("o"),
                Event = "PacketBlocked",
                Source = packet.SourceIP,
                Port = packet.DestinationPort,
                Protocol = packet.Protocol.ToString(),
                Reason = $"Blocked by Rule {ruleId}"
            };

            string jsonLine = JsonSerializer.Serialize(logEntry);

            lock (_lock)
            {
                File.AppendAllText(_logFilePath, jsonLine + Environment.NewLine);
            }
        }
        
        public void LogSystem(string message)
        {
             Console.WriteLine($"[SYSTEM] {message}");
        }
    }
}
