using System;
using System.Collections.Generic;
using System.Linq;
using SimpleFirewall.Core;
using SimpleFirewall.Network;
using SimpleFirewall.Utils;

namespace SimpleFirewall
{
    class Program
    {
        static RuleEngine _ruleEngine = null!;
        static SimpleLogger _logger = null!;
        static ManagementApi _api = null!;
        static List<ProxyListener> _listeners = new List<ProxyListener>();

        static void Main(string[] args)
        {
            Console.WriteLine("Initializing SimpleFirewall Service...");

            // 1. Setup Components
            _logger = new SimpleLogger();
            _ruleEngine = new RuleEngine();

            // 2. Load Rules
            var rules = ConfigManager.LoadRules();
            foreach (var rule in rules)
            {
                _ruleEngine.AddRule(rule);
            }

            // 3. Start API
            _api = new ManagementApi(_ruleEngine, _logger);
            _api.Start();

            // 4. Start Default Proxy (8080 -> google.com:80 for demo)
            StartProxy(8080, "google.com", 80);

            Console.WriteLine("Service Ready.");
            Console.WriteLine("Type 'help' for commands.");

            // 5. CLI Loop
            while (true)
            {
                Console.Write("> ");
                string input = Console.ReadLine();
                if (string.IsNullOrWhiteSpace(input)) continue;

                var parts = input.Split(' ');
                string command = parts[0].ToLower();

                try
                {
                    switch (command)
                    {
                        case "help":
                            ShowHelp();
                            break;
                        case "list":
                            ListRules();
                            break;
                        case "add":
                            AddRule(parts);
                            break;
                        case "del":
                            if (parts.Length > 1) _ruleEngine.RemoveRule(parts[1]);
                            else Console.WriteLine("Usage: del <RuleId>");
                            break;
                        case "save":
                            ConfigManager.SaveRules(_ruleEngine.GetRules());
                            break;
                        case "proxy":
                            if (parts.Length > 3) 
                            { 
                                // proxy <localPort> <targetHost> <targetPort>
                                if(int.TryParse(parts[1], out int lp) && int.TryParse(parts[3], out int tp))
                                     StartProxy(lp, parts[2], tp);
                            }
                            else Console.WriteLine("Usage: proxy <localPort> <targetHost> <targetPort>");
                            break;
                        case "logs":
                            ShowLogs(parts.Length > 1 ? parts[1] : null);
                            break;
                        case "quit":
                        case "exit":
                            _api.Stop();
                            foreach (var l in _listeners) l.Stop();
                            return;
                        default:
                            Console.WriteLine("Unknown command.");
                            break;
                    }
                }
                catch (Exception ex)
                {
                    Console.WriteLine($"Error: {ex.Message}");
                }
            }
        }

        static void StartProxy(int localPort, string targetHost, int targetPort)
        {
            var listener = new ProxyListener(_ruleEngine, _logger);
            listener.Start(new ProxyConfig { ListenPort = localPort, TargetHost = targetHost, TargetPort = targetPort });
            _listeners.Add(listener);
        }

        static void AddRule(string[] parts)
        {
            // add <src_ip> <port> <proto> <action> [prio]
            if (parts.Length < 5)
            {
                Console.WriteLine("Usage: add <src_ip> <port> <tcp/udp/any> <allow/deny> [priority]");
                return;
            }

            try
            {
                var rule = new FirewallRule
                {
                    SourceIP = parts[1],
                    Port = int.Parse(parts[2]),
                    Protocol = Enum.Parse<ProtocolType>(parts[3], true),
                    Action = Enum.Parse<RuleAction>(parts[4], true)
                };
                if(parts.Length > 5) rule.Priority = int.Parse(parts[5]);
                
                _ruleEngine.AddRule(rule);
            }
            catch
            {
                Console.WriteLine("Invalid arguments.");
            }
        }

        static void ListRules()
        {
            var rules = _ruleEngine.GetRules();
            foreach (var r in rules)
            {
                Console.WriteLine(r);
            }
        }

        static void ShowLogs(string filter)
        {
            if (!System.IO.File.Exists("firewall_events.jsonl"))
            {
                Console.WriteLine("No logs found.");
                return;
            }

            var lines = System.IO.File.ReadAllLines("firewall_events.jsonl");
            foreach (var line in lines)
            {
                if (filter == null || line.Contains(filter, StringComparison.OrdinalIgnoreCase))
                {
                    Console.WriteLine(line);
                }
            }
        }

        static void ShowHelp()
        {
            Console.WriteLine("Available commands:");
            Console.WriteLine("  list                   - List all rules");
            Console.WriteLine("  add <ip> <port> <proto> <action> - Add a new rule");
            Console.WriteLine("  del <id>               - Delete a rule");
            Console.WriteLine("  save                   - Save rules to disk");
            Console.WriteLine("  proxy <lport> <host> <tport> - Start proxy");
            Console.WriteLine("  logs [filter]                - Show logs (optional text filter)");
            Console.WriteLine("  quit                   - Exit");
        }
    }
}
