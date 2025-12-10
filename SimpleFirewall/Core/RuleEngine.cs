using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using SimpleFirewall.Utils;

namespace SimpleFirewall.Core
{
    public class RuleEngine
    {
        private List<FirewallRule> _rules = new List<FirewallRule>();
        private readonly object _lock = new object();

        public void AddRule(FirewallRule rule)
        {
            lock (_lock)
            {

                _rules.Add(rule);
                Console.WriteLine($"Rule added: {rule}");
                
                var conflicts = DetectConflicts(rule);
                foreach(var c in conflicts) Console.WriteLine($"Warning: {c}");
            }
        }

        public bool RemoveRule(string ruleId)
        {
            lock (_lock)
            {
                var rule = _rules.FirstOrDefault(r => r.RuleId == ruleId);
                if (rule != null)
                {
                    _rules.Remove(rule);
                    Console.WriteLine($"Rule {ruleId} removed.");
                    return true;
                }
                return false;
            }
        }
        
        public void ToggleRule(string ruleId, bool enable)
        {
             lock(_lock)
             {
                 var rule = _rules.FirstOrDefault(r => r.RuleId == ruleId);
                 if(rule != null) rule.IsEnabled = enable;
             }
        }

        public void ClearRules()
        {
            lock(_lock)
            {
                _rules.Clear();
                Console.WriteLine("All rules cleared.");
            }
        }
        
        public void UpdateRule(string id, FirewallRule update)
        {
            lock(_lock)
            {
                var rule = _rules.FirstOrDefault(r => r.RuleId == id);
                if(rule != null)
                {
                    if(update.Port != 0) rule.Port = update.Port;
                    if(update.SourcePort != 0) rule.SourcePort = update.SourcePort;
                    if(!string.IsNullOrEmpty(update.SourceIP)) rule.SourceIP = update.SourceIP;
                    if(!string.IsNullOrEmpty(update.DestIP)) rule.DestIP = update.DestIP;
                    if(update.Protocol != ProtocolType.Any) rule.Protocol = update.Protocol;

                    rule.Action = update.Action;
                    rule.IsEnabled = update.IsEnabled;
                    rule.Priority = update.Priority;
                    
                    Console.WriteLine($"Rule {id} updated.");
                }
            }
        }

        public List<FirewallRule> GetRules()
        {
            lock (_lock)
            {
                return new List<FirewallRule>(_rules);
            }
        }

        public RuleAction CheckPacket(PacketInfo packet, out string matchedRuleId)
        {
            matchedRuleId = null;
            lock (_lock)
            {

                foreach (var rule in _rules.Where(r => r.IsEnabled).OrderBy(r => r.Priority))
                {
                    if (Matches(rule, packet))
                    {
                        matchedRuleId = rule.RuleId;
                        return rule.Action;
                    }
                }
            }

            return RuleAction.Allow; 
        }

        private bool Matches(FirewallRule rule, PacketInfo packet)
        {
            if (rule.Protocol != ProtocolType.Any && rule.Protocol != packet.Protocol)
                return false;

            if (rule.Port != 0 && rule.Port != packet.DestinationPort)
                return false;
                
            if (rule.SourcePort != 0 && rule.SourcePort != packet.SourcePort)
                return false;

            if (!NetworkUtils.IsIpInCidr(packet.SourceIP, rule.SourceIP))
                return false;

            if (!NetworkUtils.IsIpInCidr(packet.DestinationIP, rule.DestIP))
                return false;

            return true;
        }

        public List<string> DetectConflicts(FirewallRule newRule)
        {
             var warnings = new List<string>();
             foreach(var existing in _rules)
             {
                 if(existing.RuleId == newRule.RuleId) continue; 

                 if(existing.SourceIP == newRule.SourceIP && 
                    existing.DestIP == newRule.DestIP &&
                    existing.Port == newRule.Port &&
                    existing.SourcePort == newRule.SourcePort &&
                    existing.Protocol == newRule.Protocol &&
                    existing.Action == newRule.Action &&
                    existing.Priority == newRule.Priority)
                 {
                     warnings.Add($"DUPLICATE: Rule {existing.RuleId} is identical.");
                 }
                 
                 if(existing.SourceIP == newRule.SourceIP && 
                    existing.Port == newRule.Port &&
                    existing.Protocol == newRule.Protocol &&
                    existing.Action != newRule.Action)
                 {
                     if(existing.Priority == newRule.Priority)
                        warnings.Add($"CONFLICT: Rule {existing.RuleId} has same criteria/priority but different Action ({existing.Action}).");
                 }
                 

             }
             return warnings;
        }

        private bool IsAnyIp(string ip) => string.IsNullOrEmpty(ip) || ip == "*" || ip == "0.0.0.0" || ip == "0.0.0.0/0";
    }
}
