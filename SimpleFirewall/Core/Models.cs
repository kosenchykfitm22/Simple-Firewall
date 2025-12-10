using System;

namespace SimpleFirewall.Core
{
    public enum RuleAction
    {
        Allow,
        Deny
    }

    public enum ProtocolType
    {
        TCP,
        UDP,
        Any
    }

    public class FirewallRule
    {
        public string RuleId { get; set; } = Guid.NewGuid().ToString();
        public bool IsEnabled { get; set; } = true;
        
        public int Priority { get; set; } = 100; // Lower value = Higher priority
        
        // Filter Criteria
        public string SourceIP { get; set; } // "192.168.1.10" or "192.168.1.0/24" (CIDR)
        public string DestIP { get; set; }   // "10.0.0.5" or CIDR
        public int SourcePort { get; set; }  // 0 for Any
        public int Port { get; set; }        // Destination Port, 0 for Any
        public ProtocolType Protocol { get; set; } // TCP, UDP, Any
        public RuleAction Action { get; set; }

        public override string ToString()
        {
            return $"[{RuleId}] Prio:{Priority} {Action} {Protocol} Src:{SourceIP}:{SourcePort} -> Dst:{DestIP}:{Port} (Enabled: {IsEnabled})";
        }
    }

    public class PacketInfo
    {
        public string SourceIP { get; set; }
        public int SourcePort { get; set; }
        public string DestinationIP { get; set; }
        public int DestinationPort { get; set; }
        public ProtocolType Protocol { get; set; }
        public DateTime Timestamp { get; set; } = DateTime.Now;
    }
}
