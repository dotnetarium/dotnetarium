using System.Security.Cryptography;
using System.Text;

namespace Dotnetarium.Tool;

internal static class SecretTokenValidation
{
    internal static bool Accept(string token)
    {
        if (token.StartsWith("glpat-", StringComparison.Ordinal))
        {
            var parts = token.Split('.');
            if (parts.Length is 1 or 2) return true; // Preserve legacy layouts; validate the current documented version.
            // Future versions remain findings; do not guess their layout.
            if (parts.Length == 3 && parts[1] != "01") return true;
            if (parts.Length is not (2 or 3) || parts[^1].Length != 9) return true;
            var payloadLength = parts[0].Length - 6;
            if (Base36(parts[^1][..2]) != payloadLength) return false;
            uint crc = 0xffffffff;
            foreach (var value in Encoding.ASCII.GetBytes(token[..^7]))
            {
                crc ^= value;
                for (var bit = 0; bit < 8; bit++) crc = (crc >> 1) ^ ((crc & 1) != 0 ? 0xedb88320u : 0);
            }
            return Base36(parts[^1][2..]) == ~crc;
        }
        if (token.StartsWith("-----BEGIN PRIVATE KEY-----", StringComparison.Ordinal))
        {
            try { using var rsa = RSA.Create(); rsa.ImportFromPem(token); return true; }
            catch (ArgumentException) { return false; }
            catch (CryptographicException) { return false; }
        }
        return GitHubTokenChecksum.Accept(token);
    }

    private static long Base36(string value)
    {
        long result = 0;
        foreach (var ch in value)
        {
            var digit = "0123456789abcdefghijklmnopqrstuvwxyz".IndexOf(ch);
            if (digit < 0) return -1;
            result = result * 36 + digit;
        }
        return result;
    }
}
