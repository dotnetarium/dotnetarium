# Reproduce target-framework inheritance from LANCommander's shared props.
# No restore or build is allowed: both property and item conditions must be read
# by the default loader, and unsupported branches must remain visible.
$conditional = Join-Path $scratch 'conditions'
$app = Join-Path $conditional 'App'
New-Item -ItemType Directory -Path $app -Force | Out-Null
@'
<Project>
  <PropertyGroup>
    <TargetFramework Condition="'$(MSBuildProjectName)' != 'LANCommander.SDK' and '$(MSBuildProjectName)' != 'LANCommander.SDK.SourceGenerators' and '$(MSBuildProjectName)' != 'LANCommander.Steam'">net10.0</TargetFramework>
    <EnableDefaultCompileItems>false</EnableDefaultCompileItems>
  </PropertyGroup>
</Project>
'@ | Set-Content -LiteralPath (Join-Path $conditional 'Directory.Build.props')
$conditionalProject = Join-Path $app 'App.csproj'
$conditionalXml = @'
<Project Sdk="Microsoft.NET.Sdk">
  <ItemGroup><FrameworkReference Include="Microsoft.AspNetCore.App" /></ItemGroup>
  <ItemGroup Condition="'$(Configuration)' == 'Debug' And ('$(Platform)' == 'AnyCPU' Or false)">
    <Compile Include="Unsafe.cs" />
  </ItemGroup>
  <ItemGroup Condition="!('$(Configuration)' == 'Debug')">
    <Compile Include="Safe.cs" />
  </ItemGroup>
</Project>
'@
$conditionalXml | Set-Content -LiteralPath $conditionalProject
@'
using System.Diagnostics;
using Microsoft.AspNetCore.Mvc;
public class Entry : Controller {
    public void Unsafe(string command) => Process.Start(command);
}
'@ | Set-Content -LiteralPath (Join-Path $app 'Unsafe.cs')
@'
using System.Diagnostics;
using Microsoft.AspNetCore.Mvc;
public class Entry : Controller {
    public void Safe(string command) => Process.Start("fixed");
}
'@ | Set-Content -LiteralPath (Join-Path $app 'Safe.cs')
$inherited = Scan $conditionalProject @()
AssertFinding $inherited
AssertMode $inherited 'no-build' 'available'
if (HasNotice $inherited 'condition') { throw 'Supported compound props/item conditions were skipped.' }
$release = Scan $conditionalProject @('--configuration', 'Release')
AssertMode $release 'no-build' 'available'
if (@($release.results | Where-Object ruleId -ne 'DNA9000').Count) { throw 'False item condition included the unsafe source.' }
$invalidXml = $conditionalXml.Replace('</Project>', '<PropertyGroup><DefineConstants Condition="true Or UnknownFunction(''marker.txt'')">UNSUPPORTED</DefineConstants></PropertyGroup></Project>')
$invalidXml | Set-Content -LiteralPath $conditionalProject
$unsupportedCondition = Scan $conditionalProject @()
AssertFinding $unsupportedCondition
if (-not (HasNotice $unsupportedCondition 'condition')) { throw 'Unsupported syntax in a short-circuited branch was hidden.' }
if (Test-Path -LiteralPath (Join-Path $app 'obj')) { throw 'No-build condition evaluation created build/restore outputs.' }
