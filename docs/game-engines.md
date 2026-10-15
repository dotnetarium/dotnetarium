# Game engine C# analysis

## Current coverage

This coverage applies to C#. GDScript, native C++ and shader source are not parsed.

Crypto and other direct API checks do not need a remote entry point. They inspect
ordinary C# bodies, including Unity `Start`/`Awake` and Godot `_Ready` methods.
Those lifecycle methods are not themselves remote-input sources.

| Input or API | Coverage |
| --- | --- |
| Godot `Node` methods with `[Rpc(MultiplayerApi.RpcMode.AnyPeer)]` | Text, bytes, Variant and Godot collection payloads are remote sources, including private methods and `CallLocal = true` |
| Unity Netcode `NetworkBehaviour` methods with `[ServerRpc]` or `[Rpc(SendTo.Server)]` | RPC payload parameters are remote sources; ownership checks do not sanitize them |
| Unity RPC context parameters | Sender/routing metadata is excluded from payload sources |
| Standard .NET and modeled library APIs | Existing file-path, process, SQL, network, XML/deserialization and crypto rules apply when their APIs resolve |
| Godot `OS.Execute`, `ExecuteWithPipe`, `CreateProcess` | Remote-controlled executable paths are command sinks; ordinary argument-array elements are not shell commands |
| Godot `AesContext.Start` | ECB encryption, provably fixed CBC encryption IVs and literal keys are checked by DNA0014, DNA0015 and DNA0009 |

ECB/CBC decryption is excluded from the native encryption-mode/IV checks.
CBC alone is not reported as a vulnerability. This avoids warning on legitimate
legacy decryption or assuming an unauthenticated protocol from a cipher API call.

Godot's default/explicit `Authority` mode is not an automatic remote source:
the authority is normally the server. Client-assigned node authority is not yet
correlated with those RPCs. Unity client-targeted RPCs, dynamic/other universal RPC
targets, Mirror, FishNet and Photon are not covered by this first input model.
Local input fields, exported properties, game asset names and lifecycle arguments
are not assumed to be network data. Numeric/math-only Godot values and object
references are excluded; RPCs do not transport arbitrary C# objects as text.

## Loading and generated code

Godot C# projects using `Godot.NET.Sdk/4.x` and targeting .NET 8 or 10 can be scanned
in project mode. No-build mode reconstructs standard GodotSharp package requests,
reads matching restored assets from `.godot/mono/temp/obj`, and excludes `.godot`
cache files from the default source inventory. Restore separately first.

Default no-build loading discloses that Godot generators and SDK targets are not
executed; platform-specific constants, custom SDK options, preview bindings and
generated signal/property/method helpers can be missing. RPC annotations and
ordinary C# method bodies exist in the original files, so they remain analyzable.
This differs from Razor templates whose executable C# bodies must be generated.
A missing `MethodName` helper is disclosed as a compiler error and does not make
the independent RPC/crypto findings disappear. Inspect coverage notices and use
`-p` project mode when generated helpers matter.

Godot validation includes real GodotSharp 4.7.2 metadata and both CLI modes on
.NET 8 and 10. The smoke test checks safe controls, source flows, missing helpers
and cache exclusion without executing the game or emitting it in no-build mode.

Unity validation currently covers compiled Netcode API contracts. End-to-end
Unity editor/project integration remains unverified. Standard Unity-generated
non-SDK `Assembly-CSharp.csproj` projects are rejected by the no-build loader with
a failure, rather than a successful empty scan. Unity editor analyzer hosts must
also satisfy this package's Roslyn 5.0 minimum; do not assume that they do.
Complete Unity CLI support needs a loader using the generated project inventory,
actual Unity reference DLLs, assembly definitions and compilation symbols.

## Useful next coverage

Prioritize engine integration and verifiable remote boundaries:

1. Validate Unity loading against real editor-generated projects and reference DLLs.
2. Correlate Godot client-assigned authority and registered packet/HTTP callbacks;
   cover Unity custom-message receivers and additional RPC targets.
3. Check explicitly unsafe Godot object deserialization, such as
   `GD.BytesToVarWithObjects`, with a separate rule and safe variant controls.
4. Review native TLS configuration with the same development/debug exceptions as
   the existing TLS rule.

Authorization, anti-cheat logic, economy validation, ordinary rich text and normal
checksum hashing require application context. They are not automatic vulnerability
findings in this slice.

See the official [Godot RPC documentation](https://docs.godotengine.org/en/stable/tutorials/networking/high_level_multiplayer.html)
and [Unity Netcode RPC contracts](https://github.com/Unity-Technologies/com.unity.netcode.gameobjects/blob/develop/com.unity.netcode.gameobjects/Runtime/Messaging/RpcAttributes.cs).
