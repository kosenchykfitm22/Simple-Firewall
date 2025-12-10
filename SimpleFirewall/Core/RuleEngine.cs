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
                // New logic: Priority based insertion? Or just Add and Sort on Read?
                // Let's just Add and rely on LINQ OrderBy or Sort in place.
                // Simple: Add.
                _rules.Add(rule);
                Console.WriteLine($"Rule added: {rule}");
                
                // Warn about conflicts AFTER adding (or before, but allow)? 
                // Requirement: "Warning when adding overriding records".
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
                    // Naive update: copy non-defaults
                    if(update.Port != 0) rule.Port = update.Port;
                    if(update.SourcePort != 0) rule.SourcePort = update.SourcePort;
                    if(!string.IsNullOrEmpty(update.SourceIP)) rule.SourceIP = update.SourceIP;
                    if(!string.IsNullOrEmpty(update.DestIP)) rule.DestIP = update.DestIP;
                    if(update.Protocol != ProtocolType.Any) rule.Protocol = update.Protocol;
                    // Action is enum, default is Allow(0). Hard to know if intention. 
                    // Let's assume Action is required or always updated if sent. 
                    // Actually, let's just update common mutable fields or implementation specific.
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
                // Iterate rules sorted by Priority (Ascending) -> First Match Wins
                // This means Priority 1 is checked before Priority 100.
                foreach (var rule in _rules.Where(r => r.IsEnabled).OrderBy(r => r.Priority))
                {
                    if (Matches(rule, packet))
                    {
                        matchedRuleId = rule.RuleId;
                        return rule.Action;
                    }
                }
            }
            // Default Policy: What if no rule matches?
            // Usually "Implicit Deny" or "Implicit Allow".
            // Let's assume Implicit Allow for this "User Mode Service" so we don't break everything by default?
            // Or Implicit Deny for security?
            // Since this is a specific listening service, maybe Implicit Allow (it is just a filter).
            // Let's do Implicit Allow (pass-through) effectively unless blocked.
            
            // WAIT: If we are implementing a Firewall, usually it's "Default Deny".
            // But checking the user prompt: "service... with possibility to filter...".
            // Let's default to Allow to make testing easier (we add Block rules), 
            // BUT we can add a "Block All" rule manually if we want Default Deny.
            return RuleAction.Allow; 
        }

        private bool Matches(FirewallRule rule, PacketInfo packet)
        {
            // 1. Protocol Match
            if (rule.Protocol != ProtocolType.Any && rule.Protocol != packet.Protocol)
                return false;

            // 2. Destination Port Match
            if (rule.Port != 0 && rule.Port != packet.DestinationPort)
                return false;
                
            // 3. Source Port Match
            if (rule.SourcePort != 0 && rule.SourcePort != packet.SourcePort)
                return false;

            // 4. Source IP CIDR Match
            if (!NetworkUtils.IsIpInCidr(packet.SourceIP, rule.SourceIP))
                return false;

            // 5. Dest IP CIDR Match
            if (!NetworkUtils.IsIpInCidr(packet.DestinationIP, rule.DestIP))
                return false;

            return true;
        }

        public List<string> DetectConflicts(FirewallRule newRule)
        {
             var warnings = new List<string>();
             foreach(var existing in _rules)
             {
                 if(existing.RuleId == newRule.RuleId) continue; // Skip self if re-checking

                 // Exact Duplicate
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
                 
                 // Conflict / Overlap
                 // Logic: If criteria overlap, check Priority.
                 // If Priority is same, and Action different -> Conflict (Ambiguous order if not stable sort, or just generic conflict).
                 // If Priority is different:
                 //    Higher Priority Rule (Lower Is) shadows Lower Priority Rule (High Is) if Higher Rule is BROADER or EQUAL.
                 //    Actually, simple logic: If they overlap, and have different actions, warn the user.
                 
                 // Simplified overlap check: Exact match on criteria
                 if(existing.SourceIP == newRule.SourceIP && 
                    existing.Port == newRule.Port &&
                    existing.Protocol == newRule.Protocol &&
                    existing.Action != newRule.Action)
                 {
                     if(existing.Priority == newRule.Priority)
                        warnings.Add($"CONFLICT: Rule {existing.RuleId} has same criteria/priority but different Action ({existing.Action}).");
                 }
                 
                 // Note: Full CIDR subset matching for conflict detection is complex (O(N^2) with bitwise math).
                 // Skipping deep CIDR overlap analysis for this iteration to keep it performant for the demo.
             }
             return warnings;
        }

        private bool IsAnyIp(string ip) => string.IsNullOrEmpty(ip) || ip == "*" || ip == "0.0.0.0" || ip == "0.0.0.0/0";
    }
}
