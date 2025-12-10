using System;
using System.IO;
using System.Net;
using System.Text;
using System.Threading.Tasks;
using System.Text.Json; 
using SimpleFirewall.Core;
using System.Linq; 

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
                var segments = request.Url.AbsolutePath.Split('/');
                if (segments.Length >= 4 && segments[1] == "rules" && segments[3] == "toggle")
                {
                    string id = segments[2];
            
                    
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
                 var segments = request.Url.AbsolutePath.Split('/');
                if (segments.Length >= 3 && segments[1] == "rules")
                {
                    string id = segments[2];
                    using (var reader = new StreamReader(request.InputStream))
                    {

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
