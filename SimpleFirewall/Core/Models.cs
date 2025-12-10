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
        
        public int Priority { get; set; } = 100; 
        
        public string SourceIP { get; set; } 
        public string DestIP { get; set; }   
        public int SourcePort { get; set; }  
        public int Port { get; set; }        
        public ProtocolType Protocol { get; set; } 
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
