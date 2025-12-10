using System;
using System.IO;
using System.Net;
using System.Text;
using System.Threading.Tasks;
using System.Text.Json; // Use System.Text.Json
using SimpleFirewall.Core;
using System.Linq; // For parsing

using SimpleFirewall.Utils;

namespace SimpleFirewall.Network
{
    public class ManagementApi
    {
        private readonly RuleEngine _ruleEngine;
        private HttpListener _httpListener;
        private bool _isRunning;
        private readonly string _url;
        private readonly SimpleLogger _logger;

        public ManagementApi(RuleEngine ruleEngine, SimpleLogger logger, string url = "http://localhost:5000/")
        {
            _ruleEngine = ruleEngine;
            _logger = logger;
            _url = url;
            _httpListener = new HttpListener();
            _httpListener.Prefixes.Add(_url);
        }

        public void Start()
        {
            try
            {
                _httpListener.Start();
                _isRunning = true;
                _logger.LogSystem($"Management API started at {_url}");
                Task.Run(() => HandleRequests());
            }
            catch(Exception ex)
            {
                Console.WriteLine($"Failed to start Management API: {ex.Message}");
            }
        }

        public void Stop()
        {
            _isRunning = false;
            _httpListener?.Stop();
        }

        private async Task HandleRequests()
        {
            while (_isRunning)
            {
                try
                {
                    var context = await _httpListener.GetContextAsync();
                    _ = ProcessRequest(context);
                }
                catch (HttpListenerException) { }
                catch (Exception ex)
                {
                     if(_isRunning) Console.WriteLine($"API Error: {ex.Message}");
                }
            }
        }

        private async Task ProcessRequest(HttpListenerContext context)
        {
            var request = context.Request;
            var response = context.Response;

            if (request.HttpMethod == "GET" && request.Url.AbsolutePath == "/rules")
            {
                var rules = _ruleEngine.GetRules();
                string json = JsonSerializer.Serialize(rules);
                byte[] buffer = Encoding.UTF8.GetBytes(json);
                response.ContentLength64 = buffer.Length;
                response.OutputStream.Write(buffer, 0, buffer.Length);
            }
            else if (request.HttpMethod == "POST" && request.Url.AbsolutePath == "/rules")
            {
                try
                {
                    using (var reader = new StreamReader(request.InputStream))
                    {
                        string body = await reader.ReadToEndAsync();
                        var rule = JsonSerializer.Deserialize<FirewallRule>(body);
                        if (rule != null)
                        {
                            _ruleEngine.AddRule(rule);
                            response.StatusCode = 200;
                        }
                        else
                        {
                            response.StatusCode = 400;
                        }
                    }
                }
                catch(Exception ex)
                {
                    response.StatusCode = 500;
                    Console.WriteLine(ex.Message);
                }
            }
            else if (request.HttpMethod == "POST" && request.Url.AbsolutePath.Contains("/toggle"))
            {
                // Format: /rules/{id}/toggle
                var segments = request.Url.AbsolutePath.Split('/');
                if (segments.Length >= 4 && segments[1] == "rules" && segments[3] == "toggle")
                {
                    string id = segments[2];
                    
                    // Simple logic: Toggle state (we need to know current state or passed via query? Let's just Flip it or set to true?)
                    // The prompt asked to "enable/disable". Let's assume this endpoint toggles.
                    // Or we could look for a query param ?enable=true
                    
                    // Let's implement toggle for simplicity, or enable=true/false query.
                    // Let's rely on reading body for specific state, or just flip.
                    // Implementation: Find rule, flip IsEnabled.
                    
                    var rules = _ruleEngine.GetRules();
                    var rule = rules.FirstOrDefault(r => r.RuleId == id);
                    if(rule != null)
                    {
                        _ruleEngine.ToggleRule(id, !rule.IsEnabled);
                        response.StatusCode = 200;
                    }
                    else
                    {
                         response.StatusCode = 404;
                    }
                }
            }
            else if (request.HttpMethod == "POST" && request.Url.AbsolutePath == "/reload")
            {
                var rules = ConfigManager.LoadRules();
                // Clear existing and re-add? Ideally RuleEngine should have Clear or SetRules.
                // For now, let's just clear internal list manually via a new method if we had one.
                // We will add `ClearRules` to RuleEngine or just loop and remove?
                // Let's assume we implement SetRules.
                // Edit RuleEngine first? No, let's keep it simple:
                 
                 // TODO: We need a clear method or just accept we append. 
                 // Actually the user wants "Reload". 
                 // "reload from config file".
                 
                 // Let's implement _ruleEngine.ClearRules() via reflection/extension or just assume we add it later 
                 // if we had time. For now, let's just re-load additively or implement the missing method? 
                 // I can modify RuleEngine to have Clear.
                 _ruleEngine.ClearRules();
                 foreach(var r in rules) _ruleEngine.AddRule(r);
                 
                 response.StatusCode = 200;
                 Console.WriteLine("Rules reloaded from disk.");
            }
            else if (request.HttpMethod == "DELETE")
            {
                // /rules/{id}
                var segments = request.Url.AbsolutePath.Split('/');
                if (segments.Length >= 3 && segments[1] == "rules")
                {
                    string id = segments[2];
                    if(_ruleEngine.RemoveRule(id)) response.StatusCode = 200;
                    else response.StatusCode = 404;
                }
            }
            else if (request.HttpMethod == "PATCH")
            {
                // /rules/{id}
                 var segments = request.Url.AbsolutePath.Split('/');
                if (segments.Length >= 3 && segments[1] == "rules")
                {
                    string id = segments[2];
                    using (var reader = new StreamReader(request.InputStream))
                    {
                        // Deserializing partial update is tricky with System.Text.Json strongly typed.
                        // We will deserialize to Dictionary or just firewall rule and copy non-nulls.
                        // Simple approach: Deserialize to FirewallRule, and manually check what changed logic?
                        // Or just "Update Rule" replacing it? PATCH usually implies partial.
                        // Impl: Replace rule logic or simple property update.
                        
                        // For this demo: We read body as FirewallRule, find existing, and update fields that are set (if we can tell).
                        // Actually, JSON serialized defaults (0 or null) are hard to distinguish from "set to 0".
                        // Let's assume the user sends the full object or we just update key fields if not default.
                        try 
                        {
                            string body = await reader.ReadToEndAsync();
                            var update = JsonSerializer.Deserialize<FirewallRule>(body);
                            _ruleEngine.UpdateRule(id, update); 
                            response.StatusCode = 200;
                        }
                        catch { response.StatusCode = 400; }
                    }
                }
            }
            else
            {
                response.StatusCode = 404;
            }

            response.Close();
        }
    }
}
