using System;
using System.Net;
using System.Net.Sockets;
using System.Threading;
using System.Threading.Tasks;
using SimpleFirewall.Core;

namespace SimpleFirewall.Network
{
    public class ProxyConfig
    {
        public int ListenPort { get; set; }
        public string TargetHost { get; set; }
        public int TargetPort { get; set; }
    }

    public class ProxyListener
    {
        private readonly RuleEngine _ruleEngine;
        private readonly SimpleLogger _logger;
        private TcpListener _listener;
        private bool _isRunning;
        private ProxyConfig _config;

        public ProxyListener(RuleEngine ruleEngine, SimpleLogger logger)
        {
            _ruleEngine = ruleEngine;
            _logger = logger;
        }

        public void Start(ProxyConfig config)
        {
            _config = config;
            _listener = new TcpListener(IPAddress.Any, config.ListenPort);
            _listener.Start();
            _isRunning = true;
            _logger.LogSystem($"Proxy Listener started: {config.ListenPort} -> {config.TargetHost}:{config.TargetPort}");

            Task.Run(() => AcceptLoop());
        }

        public void Stop()
        {
            _isRunning = false;
            _listener?.Stop();
            _logger.LogSystem($"Proxy Listener stopped on port {_config?.ListenPort}.");
        }

        private async Task AcceptLoop()
        {
            while (_isRunning)
            {
                try
                {
                    var client = await _listener.AcceptTcpClientAsync();
                    _ = HandleClient(client);
                }
                catch (ObjectDisposedException) { /* Listener stopped */ }
                catch (Exception ex)
                {
                    if (_isRunning) Console.WriteLine($"Listener Error: {ex.Message}");
                }
            }
        }

        private async Task HandleClient(TcpClient client)
        {
            TcpClient targetClient = null;
            try
            {
                var endpoint = client.Client.RemoteEndPoint as IPEndPoint;
                if (endpoint == null) return;

                string remoteIp = endpoint.Address.ToString();
                int remotePort = endpoint.Port;
                int localPort = _config.ListenPort;

                var packetInfo = new PacketInfo
                {
                    SourceIP = remoteIp,
                    SourcePort = remotePort,
                    DestinationIP = "127.0.0.1", // Simplified for localhost listener
                    DestinationPort = localPort,
                    Protocol = Core.ProtocolType.TCP,
                    Timestamp = DateTime.Now
                };

                // Check Rules
                string matchedRuleId;
                var action = _ruleEngine.CheckPacket(packetInfo, out matchedRuleId);

                if (action == RuleAction.Deny)
                {
                    _logger.LogBlock(packetInfo, matchedRuleId ?? "Unknown");
                    Console.WriteLine($"[BLOCKED] {remoteIp}:{remotePort} -> {localPort} (Rule: {matchedRuleId})");
                    client.Close();
                    return;
                }

                Console.WriteLine($"[ALLOWED] {remoteIp}:{remotePort} -> {localPort} (Rule: {matchedRuleId ?? "Default"}) -> Forwarding to {_config.TargetHost}:{_config.TargetPort}");

                // Connect to Target
                targetClient = new TcpClient();
                await targetClient.ConnectAsync(_config.TargetHost, _config.TargetPort);

                // Pipe Streams
                var clientStream = client.GetStream();
                var targetStream = targetClient.GetStream();

                var clientToTarget = clientStream.CopyToAsync(targetStream);
                var targetToClient = targetStream.CopyToAsync(clientStream);

                await Task.WhenAny(clientToTarget, targetToClient);
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Proxy Error: {ex.Message}");
            }
            finally
            {
                client?.Close();
                targetClient?.Close();
            }
        }
    }
}
