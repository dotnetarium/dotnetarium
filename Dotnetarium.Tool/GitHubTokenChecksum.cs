namespace Dotnetarium.Tool;

// CLI-only filter. A checksum establishes format integrity, never token validity.
internal static class GitHubTokenChecksum
{
    private const string Base62 = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";

    internal static bool Accept(string token)
    {
        // Fine-grained PATs and stateless installation tokens have different
        // layouts. Preserve those findings instead of guessing a checksum.
        if (token.Length != 40 || !token.StartsWith("gh", StringComparison.Ordinal) ||
            "pousr".IndexOf(token[2]) < 0 || token[3] != '_') return true;

        uint crc = uint.MaxValue;
        foreach (var character in token.AsSpan(4, 30))
        {
            crc ^= character;
            for (var bit = 0; bit < 8; bit++)
                crc = (crc >> 1) ^ ((crc & 1) != 0 ? 0xedb88320u : 0u);
        }
        ulong checksum = 0;
        foreach (var character in token.AsSpan(34, 6))
        {
            var digit = Base62.IndexOf(character);
            if (digit < 0) return false;
            checksum = checksum * 62 + (uint)digit;
        }
        return checksum == ~crc;
    }
}
