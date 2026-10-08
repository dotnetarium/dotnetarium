# Uses the CLI invocation and SARIF assertions from Test.ps1.
# Each dependency exposes a type from the next project, just as an ORM/service
# API does. Losing a transitive reference breaks overload binding at the sink.
foreach ($framework in @('net8.0', 'net10.0')) {
    $graph = Join-Path $scratch "references-$framework"
    foreach ($name in @('App', 'Bridge', 'Other', 'Data')) {
        New-Item -ItemType Directory -Path (Join-Path $graph $name) -Force | Out-Null
    }
    $data = Join-Path $graph 'Data/Data.csproj'
    '<Project Sdk="Microsoft.NET.Sdk"><PropertyGroup><TargetFramework>net8.0</TargetFramework></PropertyGroup></Project>' |
        Set-Content -LiteralPath $data
    'namespace Transit; public sealed class Root { public string Directory => "storage"; }' |
        Set-Content -LiteralPath (Join-Path $graph 'Data/Root.cs')
    foreach ($name in @('Bridge', 'Other')) {
        "<Project Sdk=`"Microsoft.NET.Sdk`"><PropertyGroup><TargetFramework>$framework</TargetFramework></PropertyGroup><ItemGroup><ProjectReference Include=`"../Data/Data.csproj`"/></ItemGroup></Project>" |
            Set-Content -LiteralPath (Join-Path $graph "$name/$name.csproj")
        "public static class $name { public static Transit.Root Get() => new Transit.Root(); }" |
            Set-Content -LiteralPath (Join-Path $graph "$name/Api.cs")
    }
    $app = Join-Path $graph 'App/App.csproj'
    $projectXml = @"
<Project Sdk="Microsoft.NET.Sdk">
  <PropertyGroup><TargetFramework>$framework</TargetFramework></PropertyGroup>
  <ItemGroup>
    <FrameworkReference Include="Microsoft.AspNetCore.App"/>
    <ProjectReference Include="../Bridge/Bridge.csproj"/>
    <ProjectReference Include="../Other/Other.csproj"/>
    <ProjectReference Include="../Missing/NotAnOutput.csproj" ReferenceOutputAssembly="false"/>
    <ProjectReference Include="../Missing/Generator.csproj" OutputItemType="Analyzer" ReferenceOutputAssembly="false"/>
  </ItemGroup>
</Project>
"@
    $projectXml | Set-Content -LiteralPath $app
    $source = @'
using System.IO;
using Microsoft.AspNetCore.Mvc;
public class EntryController : Controller {
    public void Unsafe(string input) => Directory.CreateDirectory(Path.Combine(Bridge.Get().Directory, input));
    public void Safe(string input) => Directory.CreateDirectory(Path.Combine(Other.Get().Directory, "fixed"));
}
'@
    $source | Set-Content -LiteralPath (Join-Path $graph 'App/Entry.cs')
    $direct = Scan $app @('-nb')
    AssertMode $direct 'no-build' 'partial'
    if (-not (HasNotice $direct 'generation')) { throw 'Skipped analyzer-only reference must remain a coverage warning.' }
    if (@($direct.results).Count -ne 1 -or $direct.results[0].ruleId -ne 'DNA0004' -or
        -not @($direct.results[0].codeFlows).Count -or (HasNotice $direct 'compiler-error')) {
        throw "Transitive/diamond references lost the path sink for $framework."
    }
    if (Test-Path -LiteralPath (Join-Path $graph 'App/obj')) { throw 'Direct reference loading executed restore/build.' }
    $timings = $direct.invocations[0].properties.'dotnetarium.stageSeconds'
    if ($null -eq $timings.loading -or $null -eq $timings.'analysis-total' -or
        $timings.loading -lt 0 -or $timings.'analysis-total' -lt 0) {
        throw 'Missing/nonpositive scan stage timing.'
    }
    # Restore a conventional graph and compare against the SDK loader.
    $conventional = $projectXml -replace '\s*<ProjectReference Include="../Missing/[^\n]+', ''
    $conventional | Set-Content -LiteralPath $app
    & dotnet restore $app --nologo -v quiet > (Join-Path $graph 'restore.log') 2>&1
    if ($LASTEXITCODE -ne 0) { throw "Reference fixture restore failed: $graph/restore.log" }
    $sdk = Scan $app @()
    AssertMode $sdk 'project' 'complete'
    if (($direct.results | ConvertTo-Json -Depth 40 -Compress) -ne ($sdk.results | ConvertTo-Json -Depth 40 -Compress)) {
        throw "Project/no-build transitive findings and flows differ for $framework."
    }
    $bridgeProject = Join-Path $graph 'Bridge/Bridge.csproj'
    $bridgeXml = Get-Content -LiteralPath $bridgeProject -Raw
    foreach ($metadata in @('PrivateAssets="all"', 'PrivateAssets="compile"', 'IncludeAssets="runtime"', 'ExcludeAssets="compile"')) {
        $conventional.Replace('<ProjectReference Include="../Other/Other.csproj"/>', '') | Set-Content -LiteralPath $app
        $source.Replace('Other.Get()', 'Bridge.Get()') | Set-Content -LiteralPath (Join-Path $graph 'App/Entry.cs')
        $bridgeXml.Replace('<ProjectReference Include="../Data/Data.csproj"/>', "<ProjectReference Include=`"../Data/Data.csproj`" $metadata/>") |
            Set-Content -LiteralPath $bridgeProject
        $restricted = Scan $app @('-nb')
        if (-not (HasNotice $restricted 'compiler-error') -or @($restricted.results).Count) {
            throw "Closure exposed compile assets hidden by $metadata."
        }
        & dotnet restore $app --nologo -v quiet > (Join-Path $graph 'restore.log') 2>&1
        if ($LASTEXITCODE -ne 0) { throw 'Restricted reference restore failed.' }
        $restrictedSdk = Scan $app @() 2
        if (-not (HasNotice $restrictedSdk 'compiler-error') -or @($restrictedSdk.results).Count) {
            throw "Reference restriction differs from SDK behavior for $metadata."
        }
    }
    $bridgeXml | Set-Content -LiteralPath $bridgeProject
    $source | Set-Content -LiteralPath (Join-Path $graph 'App/Entry.cs')
    # A direct alias must not gain an implicit global reference through a diamond.
    $aliased = $conventional.Replace('</ItemGroup>', '<ProjectReference Include="../Data/Data.csproj" Aliases="domain"/></ItemGroup>')
    $aliased | Set-Content -LiteralPath $app
    "extern alias domain;`n$source`npublic class AliasProbe { public domain::Transit.Root Value = new(); }" |
        Set-Content -LiteralPath (Join-Path $graph 'App/Entry.cs')
    $alias = Scan $app @('-nb')
    if (HasNotice $alias 'compiler-error') { throw 'Direct project aliases were not preserved.' }
    "extern alias domain;`n$source`npublic class AliasProbe { public Transit.Root Value = new(); }" |
        Set-Content -LiteralPath (Join-Path $graph 'App/Entry.cs')
    $hidden = Scan $app @('-nb')
    if (-not (HasNotice $hidden 'compiler-error')) { throw 'Closure exposed an alias-only project globally.' }
    # The explicit SDK opt-out must remain effective, even when dependencies load.
    $conventional.Replace('</PropertyGroup>', '<DisableTransitiveProjectReferences>true</DisableTransitiveProjectReferences></PropertyGroup>') |
        Set-Content -LiteralPath $app
    $source | Set-Content -LiteralPath (Join-Path $graph 'App/Entry.cs')
    $disabled = Scan $app @('-nb')
    if (-not (HasNotice $disabled 'compiler-error')) { throw 'DisableTransitiveProjectReferences was ignored.' }
    # Two projects use the same actual assembly with different aliases. Sharing
    # its image must not share the caller's alias visibility.
    & dotnet build $data --no-restore --nologo -v quiet > (Join-Path $graph 'build-data.log') 2>&1
    if ($LASTEXITCODE -ne 0) { throw "Reference assembly build failed: $graph/build-data.log" }
    $dll = [System.Security.SecurityElement]::Escape((Join-Path $graph 'Data/bin/Debug/net8.0/Data.dll'))
    foreach ($name in @('ExternalA', 'ExternalB')) {
        $directory = Join-Path $graph $name
        New-Item -ItemType Directory -Path $directory -Force | Out-Null
        $aliases = if ($name -eq 'ExternalA') { ' Aliases="domain"' } else { '' }
        "<Project Sdk=`"Microsoft.NET.Sdk`"><PropertyGroup><TargetFramework>$framework</TargetFramework></PropertyGroup><ItemGroup><Reference Include=`"Data`"$aliases><HintPath>$dll</HintPath></Reference></ItemGroup></Project>" |
            Set-Content -LiteralPath (Join-Path $directory "$name.csproj")
        $(if ($name -eq 'ExternalA') { 'extern alias domain; public class Demo { public domain::Transit.Root Value = new(); }' }
            else { 'public class Demo { public Transit.Root Value = new(); }' }) |
            Set-Content -LiteralPath (Join-Path $directory 'Demo.cs')
    }
    $externalSolution = Join-Path $graph 'External.slnx'
    '<Solution><Project Path="ExternalA/ExternalA.csproj"/><Project Path="ExternalB/ExternalB.csproj"/></Solution>' |
        Set-Content -LiteralPath $externalSolution
    $external = Scan $externalSolution @('-nb')
    AssertMode $external 'no-build' 'complete'
    if (@($external.results).Count -or (HasNotice $external 'compiler-error')) { throw 'Shared metadata leaked aliases between projects.' }
    "PASS ${framework}: transitive/diamond bindings, SDK parity, aliases, output filters and transitive opt-out"
}

# Cycles are reported as incomplete inputs and must not trap closure traversal.
$cycle = Join-Path $scratch 'reference-cycle'
foreach ($name in @('A', 'B')) {
    $directory = Join-Path $cycle $name
    New-Item -ItemType Directory -Path $directory -Force | Out-Null
    $other = if ($name -eq 'A') { 'B' } else { 'A' }
    "<Project Sdk=`"Microsoft.NET.Sdk`"><PropertyGroup><TargetFramework>net10.0</TargetFramework></PropertyGroup><ItemGroup><ProjectReference Include=`"../$other/$other.csproj`"/></ItemGroup></Project>" |
        Set-Content -LiteralPath (Join-Path $directory "$name.csproj")
    "public class $name { }" | Set-Content -LiteralPath (Join-Path $directory 'Demo.cs')
}
$cyclic = Scan (Join-Path $cycle 'A/A.csproj') @('-nb')
if (-not (HasNotice $cyclic 'project-reference')) { throw 'Circular project graph was not reported.' }
