using System;
using System.Net;

namespace SimpleFirewall.Utils
{
    public static class NetworkUtils
    {
        public static bool IsIpInCidr(string ipAddress, string cidr)
        {
            if (string.IsNullOrWhiteSpace(cidr) || cidr == "*" || cidr == "0.0.0.0/0" || cidr == "any") return true;

            try
            {
                if (cidr.Contains("/"))
                {
                    var parts = cidr.Split('/');
                    var baseIp = IPAddress.Parse(parts[0]);
                    var maskBits = int.Parse(parts[1]);
                    var ip = IPAddress.Parse(ipAddress);
                    return IsInSubnet(ip, baseIp, maskBits);
                }
                else
                {
                    // Exact match
                    return ipAddress == cidr;
                }
            }
            catch
            {
                // On parse error, assume no match to be safe
                return false;
            }
        }

        private static bool IsInSubnet(IPAddress address, IPAddress subnetAddress, int subnetMaskLength)
        {
            if (address.AddressFamily != subnetAddress.AddressFamily) return false;

            byte[] addressBytes = address.GetAddressBytes();
            byte[] subnetBytes = subnetAddress.GetAddressBytes();

            if (addressBytes.Length != subnetBytes.Length) return false;

            int byteCount = subnetMaskLength / 8;
            int bitCount = subnetMaskLength % 8;

            for (int i = 0; i < byteCount; i++)
            {
                if (addressBytes[i] != subnetBytes[i]) return false;
            }

            if (bitCount > 0)
            {
                int mask = 0xFF << (8 - bitCount);
                if ((addressBytes[byteCount] & mask) != (subnetBytes[byteCount] & mask)) return false;
            }

            return true;
        }
    }
}
