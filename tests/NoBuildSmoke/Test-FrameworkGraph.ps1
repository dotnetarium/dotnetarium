# SDK parity for Jellyfin-style parent imports, inherited framework contracts
# and analyzer-only restore edges. Neither loader emits the application.
foreach ($framework in @('net8.0', 'net10.0')) {
    $graph = Join-Path $scratch "framework-graph-$framework"
    foreach ($name in @('src/App', 'src/Bridge', 'src/Data', 'src/Generator')) {
        New-Item -ItemType Directory -Path (Join-Path $graph $name) -Force | Out-Null
    }
    '<Project><PropertyGroup><DefineConstants>$(DefineConstants);PARENT_PROPS</DefineConstants></PropertyGroup></Project>' |
        Set-Content -LiteralPath (Join-Path $graph 'Directory.Build.props')
    @'
<Project>
  <Import Project="$([MSBuild]::GetPathOfFileAbove('Directory.Build.props', '$(MSBuildThisFileDirectory)../'))" />
  <PropertyGroup><DefineConstants>$(DefineConstants);CHILD_PROPS</DefineConstants></PropertyGroup>
</Project>
'@ | Set-Content -LiteralPath (Join-Path $graph 'src/Directory.Build.props')
    $data = Join-Path $graph 'src/Data/Data.csproj'
    $dataXml = "<Project Sdk=`"Microsoft.NET.Sdk`"><PropertyGroup><TargetFramework>$framework</TargetFramework></PropertyGroup><ItemGroup><FrameworkReference Include=`"Microsoft.AspNetCore.App`"/></ItemGroup></Project>"
    $dataXml | Set-Content -LiteralPath $data
    'public class Data { public static string Read(string path) => path; }' |
        Set-Content -LiteralPath (Join-Path $graph 'src/Data/Data.cs')
    $bridge = Join-Path $graph 'src/Bridge/Bridge.csproj'
    $bridgeXml = "<Project Sdk=`"Microsoft.NET.Sdk`"><PropertyGroup><TargetFramework>$framework</TargetFramework></PropertyGroup><ItemGroup><ProjectReference Include=`"../Data/Data.csproj`"/><ProjectReference Include=`"../Generator/Generator.csproj`" OutputItemType=`"Analyzer`"/></ItemGroup></Project>"
    $bridgeXml | Set-Content -LiteralPath $bridge
    'public class Bridge { public static string Read(string path) => Data.Read(path); }' |
        Set-Content -LiteralPath (Join-Path $graph 'src/Bridge/Bridge.cs')
    $generator = Join-Path $graph 'src/Generator/Generator.csproj'
    "<Project Sdk=`"Microsoft.NET.Sdk`"><PropertyGroup><TargetFramework>$framework</TargetFramework></PropertyGroup></Project>" |
        Set-Content -LiteralPath $generator
    'public class GeneratorOnlyType {}' | Set-Content -LiteralPath (Join-Path $graph 'src/Generator/Generator.cs')
    $app = Join-Path $graph 'src/App/App.csproj'
    $appXml = "<Project Sdk=`"Microsoft.NET.Sdk`"><PropertyGroup><TargetFramework>$framework</TargetFramework></PropertyGroup><ItemGroup><PackageReference Include=`"Newtonsoft.Json`" Version=`"13.0.4`"/><ProjectReference Include=`"../Bridge/Bridge.csproj`"/><ProjectReference Include=`"../Generator/Generator.csproj`" OutputItemType=`"Analyzer`"/><ProjectReference Include=`"../Data/Data.csproj`" ReferenceOutputAssembly=`"false`"/></ItemGroup></Project>"
    $appXml | Set-Content -LiteralPath $app
    $source = @'
#if !PARENT_PROPS || !CHILD_PROPS
#error Missing parent imports
#endif
using Microsoft.AspNetCore.Mvc;
public class EntryController : Controller {
    public Newtonsoft.Json.Linq.JObject Payload => new();
    public string Unsafe(string path) => System.IO.File.ReadAllText(Bridge.Read(path));
    public string Safe(string path) => System.IO.File.ReadAllText(Bridge.Read("fixed.txt"));
}
'@
    $entry = Join-Path $graph 'src/App/Entry.cs'
    $source | Set-Content -LiteralPath $entry
    & dotnet restore $app --nologo -v quiet > (Join-Path $graph 'restore.log') 2>&1
    if ($LASTEXITCODE -ne 0) { throw "Framework graph restore failed: $graph/restore.log" }
    $runs = @()
    foreach ($flags in @(@('--framework', $framework), @('-p', '--framework', $framework))) {
        $run = Scan $app $flags
        $runs += $run
        foreach ($id in @('import', 'compiler-error', 'package-assets-stale', 'package-assets-unverified', 'project-reference')) {
            if (HasNotice $run $id) { throw "Fresh framework/analyzer graph rejected: $framework, $id" }
        }
        if (@($run.results | Where-Object ruleId -eq 'DNA0004').Count -ne 1) { throw 'Missing inherited ASP.NET controller path flow.' }
        if (-not ($flags -contains '-p') -and
            @($run.invocations[0].properties.'dotnetarium.analyzedProjects').Count -ne 3) {
            throw 'Analyzer-only dependency became an analyzed compilation.'
        }
    }
    if (($runs[0].results | ConvertTo-Json -Depth 50 -Compress) -ne ($runs[1].results | ConvertTo-Json -Depth 50 -Compress)) {
        throw 'Inherited framework findings/flows differ from SDK mode.'
    }
    # Restore metadata must not make analyzer types visible to the application.
    ($source + "`npublic class Probe { public GeneratorOnlyType Value; }") | Set-Content -LiteralPath $entry
    $isolated = Scan $app @()
    if (-not (HasNotice $isolated 'compiler-error')) { throw 'Analyzer types leaked into compiler references.' }
    $source | Set-Content -LiteralPath $entry
    # A changed analyzer-only request still invalidates saved package bindings.
    $appXml.Replace('<ProjectReference Include="../Generator/Generator.csproj" OutputItemType="Analyzer"/>', '') |
        Set-Content -LiteralPath $app
    $stale = Scan $app @()
    if (-not (HasNotice $stale 'package-assets-stale')) { throw 'Changed analyzer-only restore graph was accepted.' }
    $appXml | Set-Content -LiteralPath $app
    # Private framework references and private downstream project edges must
    # not manufacture an ASP.NET contract for their consumers.
    foreach ($restriction in @('framework', 'project')) {
        $dataXml.Replace('<FrameworkReference Include="Microsoft.AspNetCore.App"/>', $(if ($restriction -eq 'framework') {
            '<FrameworkReference Include="Microsoft.AspNetCore.App" PrivateAssets="all"/>'
        } else { '<FrameworkReference Include="Microsoft.AspNetCore.App"/>' })) | Set-Content -LiteralPath $data
        $bridgeXml.Replace('<ProjectReference Include="../Data/Data.csproj"/>', $(if ($restriction -eq 'project') {
            '<ProjectReference Include="../Data/Data.csproj" PrivateAssets="all"/>'
        } else { '<ProjectReference Include="../Data/Data.csproj"/>' })) | Set-Content -LiteralPath $bridge
        & dotnet restore $app --nologo -v quiet > (Join-Path $graph 'restore.log') 2>&1
        if ($LASTEXITCODE -ne 0) { throw 'Private framework graph restore failed.' }
        foreach ($flags in @(@('--framework', $framework), @('-p', '--framework', $framework))) {
            $restricted = Scan $app $flags
            if (-not (HasNotice $restricted 'compiler-error')) { throw "Private $restriction contract was exposed." }
        }
    }
}
