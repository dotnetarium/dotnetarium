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
        public static readonly DiagnosticDescriptor HardcodedSecret = Create("DNA0009", "Hard-coded secrets in code", "A hardcoded {0} is passed to '{1}'.", 798);
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

        public static readonly DiagnosticDescriptor EmbeddedProviderCredential = Create("DNA0022", "Hard-coded network credentials", "A {0} {1} is hard-coded in a configuration file. Remove it and use a secret store; rotate it if exposed.", 798);
        public static readonly DiagnosticDescriptor UnsafeBinaryFormatter = Taint("DNA0023", "Unsafe BinaryFormatter deserialization", 502);
        public static readonly DiagnosticDescriptor CredentialedCors = Create("DNA0024", "Unrestricted credentialed CORS", "Applied CORS policy '{0}' accepts every origin and allows credentials. Restrict it to trusted origins.", 942);

        private static readonly IReadOnlyDictionary<string, int> CweById = new Dictionary<string, int>
        {
            ["DNA0001"] = 89, ["DNA0002"] = 78, ["DNA0003"] = 79, ["DNA0004"] = 22,
            ["DNA0005"] = 601, ["DNA0006"] = 90, ["DNA0007"] = 643, ["DNA0008"] = 502, ["DNA0023"] = 502,
            ["DNA0009"] = 798, ["DNA0010"] = 614, ["DNA0011"] = 918, ["DNA0012"] = 94,
            ["DNA0013"] = 327, ["DNA0014"] = 327, ["DNA0015"] = 329, ["DNA0016"] = 916,
            ["DNA0017"] = 321, ["DNA0018"] = 209, ["DNA0019"] = 319, ["DNA0020"] = 295, ["DNA0021"] = 611, ["DNA0022"] = 798, ["DNA0024"] = 942
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
                    "DNA0001" => "Building SQL command text from untrusted input can let a caller change the query and read or modify unintended records.",
                    "DNA0002" => "A user-controlled executable name or command string can change which program runs or what it does. The risk depends on the program and the arguments it accepts.",
                    "DNA0003" => "Rendering untrusted content as HTML can allow script to run in another user's browser with access to that page and session.",
                    "DNA0004" => "An untrusted path used for file access, extraction or code loading may select files outside the intended location. A finding does not by itself establish that an allowed root was escaped.",
                    "DNA0005" => "A user-controlled redirect destination can send users to an attacker-controlled site, including when they return from authentication.",
                    "DNA0006" => "Unescaped input in an LDAP filter or distinguished name can change a directory operation. Filters and distinguished names require different escaping rules.",
                    "DNA0007" => "An XPath expression built from untrusted input can select unintended XML data or change a check based on the query result.",
                    "DNA0008" => "Json.NET type-name handling allows JSON to select .NET types. Unrestricted type selection can be dangerous when the settings are used to deserialize untrusted JSON.",
                    "DNA0009" => "Passwords and cryptographic keys embedded in code can be recovered from source or distributed applications. This rule checks literal values used by security-sensitive APIs.",
                    "DNA0010" => "Explicit cookie settings can expose authentication or session cookies to scripts or insecure transport. SameSite=None also requires a secure cookie for modern browser compatibility.",
                    "DNA0011" => "A user-controlled outbound request destination may let an attacker reach services available to the server or send requests under its network identity.",
                    "DNA0012" => "Compiling or evaluating untrusted code may give a caller access to application data and resources with the process's permissions.",
                    "DNA0013" => "DES, TripleDES and RC2 are unsuitable for new encryption. Cipher creation may also belong to a legacy decryption path that needs separate review.",
                    "DNA0014" => "ECB encryption reveals repeated plaintext blocks. A mode assignment or cipher selection may also be used only for legacy decryption.",
                    "DNA0015" => "A fixed encryption IV or nonce can expose relationships between messages. Repeating an AEAD nonce with the same key can also allow forgery.",
                    "DNA0016" => "A low PBKDF2 iteration count makes offline password guessing cheaper. The rule's detection threshold is not a recommended secure work factor.",
                    "DNA0017" => "A post-quantum private key embedded in code can be recovered from the source or application binary. Algorithm strength does not protect an exposed private key.",
                    "DNA0018" => "Detailed gRPC errors can disclose exception information to clients. Details useful during development may expose application information in a deployed service.",
                    "DNA0019" => "Sending gRPC call credentials over plaintext HTTP exposes them to observers on the network path.",
                    "DNA0020" => "An accept-all certificate callback removes TLS peer authentication. An attacker able to intercept the connection may impersonate the service even when HTTPS is used.",
                    "DNA0021" => "An XML parser with unrestricted external resolution can access local files or network resources selected by an untrusted document.",
                    "DNA0022" => "A provider credential in configuration can be recovered from the file or repository history. Recognizing its format does not establish that the credential is still active.",
                    "DNA0023" => "BinaryFormatter can execute dangerous behavior while deserializing untrusted data. The unsupported compatibility package restores the unsafe implementation on modern .NET.",
                    "DNA0024" => "A CORS policy that accepts every origin and allows credentials may let an untrusted website read authenticated responses when the browser sends usable credentials.",
                    _ => title
                },
                helpLinkUri: $"https://github.com/dotnetarium/dotnetarium/blob/main/docs/rules/{id}.md",
                customTags: id == "DNA0010"
                    ? new[] { "CWE-614", "CWE-1004", "CWE-1275" }
                    : new[] { $"CWE-{cwe}" });
    }
}
