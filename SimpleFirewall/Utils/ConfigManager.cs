using System;
using System.Collections.Generic;
using System.IO;
using System.Text.Json;
using SimpleFirewall.Core;

namespace SimpleFirewall.Utils
{
    public static class ConfigManager
    {
        private const string ConfigFile = "rules.json";

        public static void SaveRules(List<FirewallRule> rules)
        {
            try
            {
                var options = new JsonSerializerOptions { WriteIndented = true };
                string json = JsonSerializer.Serialize(rules, options);
                File.WriteAllText(ConfigFile, json);
                Console.WriteLine("Rules saved successfully.");
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Error saving rules: {ex.Message}");
            }
        }

        public static List<FirewallRule> LoadRules()
        {
            if (!File.Exists(ConfigFile))
                return new List<FirewallRule>();

            try
            {
                string json = File.ReadAllText(ConfigFile);
                return JsonSerializer.Deserialize<List<FirewallRule>>(json) ?? new List<FirewallRule>();
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Error loading rules: {ex.Message}");
                return new List<FirewallRule>();
            }
        }
    }
}
