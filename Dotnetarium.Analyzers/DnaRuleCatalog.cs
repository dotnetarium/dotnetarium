using System.Collections.Generic;
using Microsoft.CodeAnalysis;

namespace Dotnetarium.Analyzers
{
    /// <summary>Stable diagnostic identities for the 2.x C# analyzer.</summary>
    public static class DnaRuleCatalog
    {
        public static readonly DiagnosticDescriptor SqlInjection = Taint("DNA0001", "SQL injection", 89);
        public static readonly DiagnosticDescriptor CommandInjection = Taint("DNA0002", "OS command injection", 78);
        public static readonly DiagnosticDescriptor CrossSiteScripting = Taint("DNA0003", "Cross-site scripting", 79);
        public static readonly DiagnosticDescriptor PathEscape = Taint("DNA0004", "Untrusted file path", 22);
        public static readonly DiagnosticDescriptor OpenRedirect = Taint("DNA0005", "Open redirect", 601);
        public static readonly DiagnosticDescriptor LdapInjection = Taint("DNA0006", "LDAP injection", 90);
        public static readonly DiagnosticDescriptor XPathInjection = Taint("DNA0007", "XPath injection", 643);
        public static readonly DiagnosticDescriptor UnsafeDeserializationSetting = Create("DNA0008", "Risky Json.NET polymorphism setting", "Json.NET TypeNameHandling value '{0}' can materialize unexpected types if untrusted JSON is deserialized.", 502);
        public static readonly DiagnosticDescriptor HardcodedSecret = Create("DNA0009", "Hardcoded secret", "A hardcoded {0} is passed to '{1}'.", 798);
        public static readonly DiagnosticDescriptor CookieConfiguration = Create("DNA0010", "Insecure cookie configuration", "Cookie '{0}' has unsafe settings: {1}.", 614);
        public static readonly DiagnosticDescriptor ServerSideRequestForgery = Taint("DNA0011", "Server-side request forgery", 918);
        public static readonly DiagnosticDescriptor DynamicCodeExecution = Taint("DNA0012", "Dynamic code execution", 94);
        public static readonly DiagnosticDescriptor WeakCipher = Create("DNA0013", "Legacy cipher use", "'{0}' uses a legacy cipher; review whether it encrypts new data or only decrypts existing data.", 327);
        public static readonly DiagnosticDescriptor EcbMode = Create("DNA0014", "ECB mode use", "'{0}' selects ECB; if used for encryption, repeated plaintext blocks can be revealed.", 327);
        public static readonly DiagnosticDescriptor FixedNonce = Create("DNA0015", "Fixed encryption IV or nonce", "'{0}' encrypts with a fixed IV or nonce; generate a fresh value for each encryption.", 329);
        public static readonly DiagnosticDescriptor WeakPbkdf2 = Create("DNA0016", "Low PBKDF2 work factor", "PBKDF2 iteration count {0} is too low for password-derived keys.", 916);
        public static readonly DiagnosticDescriptor HardcodedPqcPrivateKey = Create("DNA0017", "Hardcoded post-quantum private key", "'{0}' imports literal post-quantum private key material.", 321);
        public static readonly DiagnosticDescriptor GrpcDetailedErrors = Create("DNA0018", "Detailed gRPC errors enabled", "gRPC detailed errors can expose exception information to clients.", 209);
        public static readonly DiagnosticDescriptor GrpcInsecureCallCredentials = Create("DNA0019", "gRPC call credentials over plaintext", "This gRPC channel is configured to send call credentials over an insecure connection.", 319);
        public static readonly DiagnosticDescriptor CertificateValidationBypass = Create("DNA0020", "TLS certificate validation bypass", "The certificate validation callback configured for '{0}' accepts any certificate without validating it.", 295);
        public static readonly DiagnosticDescriptor XmlExternalEntity = Taint("DNA0021", "XML external entity resolution", 611);

        public static readonly DiagnosticDescriptor EmbeddedProviderCredential = Create("DNA0022", "Embedded provider credential", "A {0} {1} is embedded in a configuration file. Remove it and use a secret store; rotate it if exposed.", 798);

        private static readonly IReadOnlyDictionary<string, int> CweById = new Dictionary<string, int>
        {
            ["DNA0001"] = 89, ["DNA0002"] = 78, ["DNA0003"] = 79, ["DNA0004"] = 22,
            ["DNA0005"] = 601, ["DNA0006"] = 90, ["DNA0007"] = 643, ["DNA0008"] = 502,
            ["DNA0009"] = 798, ["DNA0010"] = 614, ["DNA0011"] = 918, ["DNA0012"] = 94,
            ["DNA0013"] = 327, ["DNA0014"] = 327, ["DNA0015"] = 329, ["DNA0016"] = 916,
            ["DNA0017"] = 321, ["DNA0018"] = 209, ["DNA0019"] = 319, ["DNA0020"] = 295, ["DNA0021"] = 611, ["DNA0022"] = 798
        };

        public static bool TryGetCwe(string id, out int cwe) => CweById.TryGetValue(id, out cwe);

        private static DiagnosticDescriptor Taint(string id, string title, int cwe) =>
            Create(id, title, $"Potential {title.ToLowerInvariant()} where '{{0}}' in '{{1}}' receives untrusted data from '{{2}}' in '{{3}}'.", cwe);

        private static DiagnosticDescriptor Create(string id, string title, string message, int cwe) =>
            new DiagnosticDescriptor(
                id,
                title,
                message,
                "Security",
                DiagnosticSeverity.Warning,
                isEnabledByDefault: true,
                description: id switch
                {
                    "DNA0008" => "CWE-502. Review non-default Json.NET type-name handling when deserializing untrusted data.",
                    "DNA0009" => "CWE-798. A literal credential or cryptographic key reaches a security-sensitive API.",
                    "DNA0010" => "Review explicit authentication, session, or cross-site cookie settings.",
                    "DNA0013" or "DNA0014" => $"CWE-{cwe}. Review whether the configured cipher is used for encryption.",
                    "DNA0015" => "CWE-329. Encryption uses provably fixed IV or nonce material.",
                    "DNA0016" => "CWE-916. An explicit PBKDF2 work factor is below a conservative minimum.",
                    "DNA0017" => "CWE-321. Literal post-quantum private key material is imported.",
                    "DNA0018" => "CWE-209. Detailed gRPC exception messages are enabled for a registered service.",
                    "DNA0019" => "CWE-319. Call credentials are configured for a plaintext gRPC channel.",
                    "DNA0020" => "CWE-295. A TLS certificate validation callback is configured to accept every certificate. Retain platform validation or validate the remote certificate explicitly.",
                    "DNA0021" => "CWE-611. Untrusted XML reaches a parser explicitly configured for DTD parsing and unrestricted external resolution. Modern safe defaults and restricted/preloaded resolvers are not reported.",
                    "DNA0022" => "CWE-798. A configuration file contains a recognizable secret provider credential. Detection checks format only, without network validation. Public identifiers are not reported.",
                    _ => $"CWE-{cwe}. Review the reported data flow and use a context-appropriate mitigation."
                },
                helpLinkUri: $"https://github.com/dotnetarium/dotnetarium/blob/main/docs/rules/{id}.md",
                customTags: id == "DNA0010"
                    ? new[] { "CWE-614", "CWE-1004", "CWE-1275" }
                    : new[] { $"CWE-{cwe}" });
    }
}
