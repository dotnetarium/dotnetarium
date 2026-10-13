using Dotnetarium.Analyzers.Cryptography;
using Dotnetarium.Analyzers.Taint;

namespace Dotnetarium.Analyzers.Tests;

public sealed class GameEngineTests
{
    [Theory]
    [InlineData("[Rpc(MultiplayerApi.RpcMode.AnyPeer)]", "input", 1)]
    [InlineData("[Rpc(MultiplayerApi.RpcMode.AnyPeer, CallLocal = true)]", "input", 1)]
    [InlineData("[Rpc(mode: MultiplayerApi.RpcMode.AnyPeer)]", "input", 1)]
    [InlineData("[Rpc]", "input", 0)]
    [InlineData("[Rpc(MultiplayerApi.RpcMode.Authority)]", "input", 0)]
    [InlineData("", "input", 0)]
    [InlineData("[Rpc(MultiplayerApi.RpcMode.AnyPeer)]", "\"fixed.txt\"", 0)]
    public async Task Godot_remote_rpc_payloads_are_sources_without_generated_helpers(string attribute, string path, int expected)
    {
        var source = "using Godot; public partial class Demo : Node { " + attribute +
            " private void Receive(string input) { _ = System.IO.File.ReadAllText(" + path + "); } }";
        var diagnostics = await FrameworkProbe.Analyze(source, new PathTraversalTaintAnalyzer());
        Assert.Equal(expected, diagnostics.Count(d => d.Id == "DNA0004"));
    }

    [Theory]
    [InlineData("Execute")]
    [InlineData("ExecuteWithPipe")]
    [InlineData("CreateProcess")]
    public async Task Godot_process_paths_are_sinks_but_plain_arguments_are_not(string method)
    {
        var source = "using Godot; public partial class Demo : Node { [Rpc(MultiplayerApi.RpcMode.AnyPeer)] " +
            "private void Receive(string input) { _ = OS." + method + "(input, new string[0]); _ = OS." + method +
            "(\"fixed-program\", new[] { input }); } }";
        var diagnostics = await FrameworkProbe.Analyze(source, new CommandInjectionTaintAnalyzer());
        Assert.Single(diagnostics.Where(d => d.Id == "DNA0002"));
    }

    [Theory]
    [InlineData("Variant", "input.AsString()", 1)]
    [InlineData("byte[]", "System.Text.Encoding.UTF8.GetString(input)", 1)]
    [InlineData("Vector3", "input.ToString()", 0)]
    [InlineData("Node", "input.Name.ToString()", 0)]
    public async Task Godot_payloads_distinguish_text_and_bytes_from_math_and_object_references(string type, string path, int expected)
    {
        var source = "using Godot; public partial class Demo : Node { [Rpc(MultiplayerApi.RpcMode.AnyPeer)] " +
            "private void Receive(" + type + " input) { _ = System.IO.File.ReadAllText(" + path + "); } }";
        var diagnostics = await FrameworkProbe.Analyze(source, new PathTraversalTaintAnalyzer());
        Assert.Equal(expected, diagnostics.Count(d => d.Id == "DNA0004"));
    }

    [Theory]
    [InlineData("[ServerRpc]", "input", 1)]
    [InlineData("[ServerRpc(RequireOwnership = true)]", "input", 1)]
    [InlineData("[Rpc(SendTo.Server)]", "input", 1)]
    [InlineData("[ClientRpc]", "input", 0)]
    [InlineData("[Rpc(SendTo.NotServer)]", "input", 0)]
    [InlineData("", "input", 0)]
    [InlineData("[ServerRpc]", "\"safe.txt\"", 0)]
    public async Task Unity_server_rpc_contracts_establish_remote_payloads(string attribute, string path, int expected)
    {
        var source = UnityContracts + "public class Demo : Unity.Netcode.NetworkBehaviour { " + attribute +
            " private void Receive(string input) { _ = System.IO.File.ReadAllText(" + path + "); } }";
        var diagnostics = await FrameworkProbe.Analyze(source, new PathTraversalTaintAnalyzer());
        Assert.Equal(expected, diagnostics.Count(d => d.Id == "DNA0004"));
    }

    [Fact]
    public async Task Unity_rpc_context_metadata_is_not_payload()
    {
        var source = UnityContracts + """
            public class Demo : Unity.Netcode.NetworkBehaviour {
                [ServerRpc] private void Receive(string input, Unity.Netcode.ServerRpcParams context) {
                    _ = System.IO.File.ReadAllText(context.Receive.SenderClientId.ToString());
                }
            }
            """;
        Assert.Empty(await FrameworkProbe.Analyze(source, new PathTraversalTaintAnalyzer()));
    }

    [Theory]
    [InlineData("using Godot; public partial class Demo : Node { public override void _Ready() { _ = System.Security.Cryptography.DES.Create(); } }", "DNA0013")]
    [InlineData("using Godot; public partial class Demo : Node { public override void _Ready() { using var aes = System.Security.Cryptography.Aes.Create(); aes.Mode = System.Security.Cryptography.CipherMode.ECB; } }", "DNA0014")]
    [InlineData("public class Demo : Unity.Netcode.NetworkBehaviour { private void Start() { _ = System.Security.Cryptography.DES.Create(); } }", "DNA0013")]
    public async Task Crypto_rules_do_not_require_an_rpc_or_browser_source(string body, string rule)
    {
        var diagnostics = await FrameworkProbe.Analyze(UnityContracts + body.Replace("using Godot;", "").Replace(": Node", ": Godot.Node"), new CryptographyAnalyzer());
        Assert.Single(diagnostics.Where(d => d.Id == rule));
    }

    [Theory]
    [InlineData("EcbEncrypt", "new byte[16]", "DNA0014")]
    [InlineData("EcbDecrypt", "new byte[16]", null)]
    [InlineData("CbcEncrypt", "new byte[16]", "DNA0015")]
    [InlineData("CbcEncrypt", "System.Security.Cryptography.RandomNumberGenerator.GetBytes(16)", null)]
    [InlineData("CbcDecrypt", "new byte[16]", null)]
    public async Task Godot_native_aes_checks_encryption_mode_and_iv(string mode, string iv, string? rule)
    {
        var source = "using Godot; public partial class Demo : Node { public override void _Ready() { var aes = new AesContext(); " +
            "aes.Start(AesContext.Mode." + mode + ", System.Security.Cryptography.RandomNumberGenerator.GetBytes(32), " + iv + "); } }";
        var diagnostics = await FrameworkProbe.Analyze(source, new CryptographyAnalyzer());
        if (rule == null) Assert.Empty(diagnostics);
        else Assert.Equal(rule, Assert.Single(diagnostics).Id);
    }

    // Focused Unity API contracts, not an installed Unity runtime. Godot tests
    // above reference the real GodotSharp package. The CLI support boundary is
    // tested separately; passing these contracts does not prove Unity loading.
    private const string UnityContracts = """
        using Unity.Netcode;
        namespace Unity.Netcode {
            public class NetworkBehaviour { }
            public enum SendTo { Server, NotServer }
            public class RpcAttribute : System.Attribute { public RpcAttribute(SendTo target) { } public bool RequireOwnership; }
            public class ServerRpcAttribute : System.Attribute { public bool RequireOwnership; }
            public class ClientRpcAttribute : System.Attribute { }
            public struct ServerRpcParams { public ServerRpcReceiveParams Receive; }
            public struct ServerRpcReceiveParams { public ulong SenderClientId; }
        }
        """;
}
