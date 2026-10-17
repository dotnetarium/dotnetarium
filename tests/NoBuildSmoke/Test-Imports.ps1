# Imported framework aliases (OrchardCore), .csproj property imports (BTCPay),
# declaration order, defining-file context and framework-specific imports.
$imports = Join-Path $scratch 'imports'
foreach ($folder in @('App', 'Build/Nested')) {
    New-Item -ItemType Directory -Path (Join-Path $imports $folder) -Force | Out-Null
}
$importProject = Join-Path $imports 'App/App.csproj'
@'
<Project>
  <Import Project="Build/Frameworks.props" />
</Project>
'@ | Set-Content -LiteralPath (Join-Path $imports 'Directory.Build.props')
@'
<Project>
  <PropertyGroup><CommonTargetFrameworks Condition="'$(CommonTargetFrameworks)' == ''">net8.0</CommonTargetFrameworks></PropertyGroup>
  <Import Project="Nested/Defaults.csproj" />
</Project>
'@ | Set-Content -LiteralPath (Join-Path $imports 'Build/Frameworks.props')
@'
<Project>
  <PropertyGroup><EnableDefaultCompileItems>false</EnableDefaultCompileItems><ImportOrder>before</ImportOrder></PropertyGroup>
  <ImportGroup Condition="'$(TargetFramework)' == 'net10.0'">
    <Import Project="Selected.props" Condition="Exists('$(MSBuildThisFileDirectory)Selected.props')" />
  </ImportGroup>
  <Import Project="Missing.props" Condition="!Exists('$(MSBuildThisFileDirectory)Selected.props')" />
</Project>
'@ | Set-Content -LiteralPath (Join-Path $imports 'Build/Nested/Defaults.csproj')
@'
<Project>
  <ItemGroup>
    <Compile Include="$(MSBuildThisFileDirectory)Entry.cs" />
    <FrameworkReference Include="Microsoft.AspNetCore.App" />
  </ItemGroup>
  <Target Name="NeverRun"><Error Text="Static imports must never execute targets" /></Target>
</Project>
'@ | Set-Content -LiteralPath (Join-Path $imports 'Build/Nested/Selected.props')
Copy-Item -LiteralPath (Join-Path $conditional 'App/Unsafe.cs') -Destination (Join-Path $imports 'Build/Nested/Entry.cs')
@'
<Project Sdk="Microsoft.NET.Sdk">
  <PropertyGroup><CommonTargetFrameworks>net10.0</CommonTargetFrameworks></PropertyGroup>
  <Import Project="../Build/Root.csproj" />
</Project>
'@ | Set-Content -LiteralPath $importProject
@'
<Project>
  <PropertyGroup><TargetFrameworks>$(CommonTargetFrameworks)</TargetFrameworks><ImportOrder>$(ImportOrder);after</ImportOrder></PropertyGroup>
  <PropertyGroup Condition="'$(ImportOrder)' == 'before;after'"><DefineConstants>IMPORT_ORDER</DefineConstants></PropertyGroup>
</Project>
'@ | Set-Content -LiteralPath (Join-Path $imports 'Build/Root.csproj')
# The marker is a compile-time assertion that imports ran at their declaration.
Add-Content -LiteralPath (Join-Path $imports 'Build/Nested/Entry.cs') -Value "`n#if !IMPORT_ORDER`n#error Wrong import order`n#endif"
$importRun = Scan $importProject @()
AssertFinding $importRun
if (HasNotice $importRun 'import') { throw 'Readable nested or false imports were reported as unsupported.' }
if (HasNotice $importRun 'compiler-error') { throw 'Imported compiler inputs were not preserved.' }
if (@($importRun.invocations[0].properties.'dotnetarium.analyzedProjects').Count -ne 1) { throw 'Imported framework alias did not select one project.' }
if (Test-Path -LiteralPath (Join-Path $imports 'App/obj')) { throw 'Static imports executed build or restore.' }
& dotnet restore $importProject --nologo -v quiet > (Join-Path $imports 'restore.log') 2>&1
if ($LASTEXITCODE -ne 0) { throw 'Imported fixture restore failed.' }
$importAware = Scan $importProject @('-p')
AssertFinding $importAware
if (($importRun.results | ConvertTo-Json -Depth 30 -Compress) -ne ($importAware.results | ConvertTo-Json -Depth 30 -Compress)) {
    throw 'Imported inputs produce different findings/flows in project mode.'
}
# A repeated, non-recursive import must still apply its properties each time.
@'
<Project><PropertyGroup><ImportOrder>before</ImportOrder></PropertyGroup></Project>
'@ | Set-Content -LiteralPath (Join-Path $imports 'Build/Repeat.props')
@'
<Project Sdk="Microsoft.NET.Sdk">
  <PropertyGroup><CommonTargetFrameworks>net10.0</CommonTargetFrameworks><ImportOrder>wrong</ImportOrder></PropertyGroup>
  <Import Project="../Build/Repeat.props" />
  <PropertyGroup><ImportOrder>wrong</ImportOrder></PropertyGroup>
  <Import Project="../Build/Repeat.props" />
  <Import Project="../Build/Root.csproj" />
</Project>
'@ | Set-Content -LiteralPath $importProject
$repeated = Scan $importProject @()
AssertFinding $repeated
if (HasNotice $repeated 'import') { throw 'Repeated non-recursive import was rejected.' }
# A cycle is bounded and disclosed while later usable inputs still load.
'<Project><Import Project="Cycle.props" /></Project>' | Set-Content -LiteralPath (Join-Path $imports 'Build/Cycle.props')
$cycleXml = (Get-Content -LiteralPath $importProject -Raw).Replace('</Project>', '<Import Project="../Build/Cycle.props" /></Project>')
$cycleXml | Set-Content -LiteralPath $importProject
$cycle = Scan $importProject @()
AssertFinding $cycle
if (-not (HasNotice $cycle 'import')) { throw 'Import cycle was not disclosed.' }
# Explicit official SDK imports must match the SDK attribute form.
$explicit = $cycleXml.Replace('<Project Sdk="Microsoft.NET.Sdk">', '<Project><Import Project="Sdk.props" Sdk="Microsoft.NET.Sdk" />').Replace('</Project>', '<Import Project="Sdk.targets" Sdk="Microsoft.NET.Sdk" /></Project>')
$explicit | Set-Content -LiteralPath $importProject
$explicitRun = Scan $importProject @()
AssertFinding $explicitRun
if (HasNotice $explicitRun 'compiler-error') { throw 'Explicit SDK imports changed source compilation.' }
# Unresolved aliases get a specific diagnosis instead of a fake unsupported TFM.
'<Project Sdk="Microsoft.NET.Sdk"><PropertyGroup><TargetFramework>$(UnknownTfm)</TargetFramework></PropertyGroup></Project>' | Set-Content -LiteralPath $importProject
$unknown = Scan $importProject @() 2
if (-not ($unknown.invocations[0].toolExecutionNotifications.message.text -match 'Unresolved TargetFramework')) { throw 'Unresolved framework alias was not diagnosed.' }
# Documentation-only SDK projects must not fail an otherwise usable solution.
$docs = Join-Path $scratch 'empty-docs'
New-Item -ItemType Directory -Path $docs -Force | Out-Null
'<Project Sdk="Microsoft.NET.Sdk"><PropertyGroup><TargetFramework>net10.0</TargetFramework></PropertyGroup></Project>' | Set-Content -LiteralPath (Join-Path $docs 'Docs.csproj')
$explicit | Set-Content -LiteralPath $importProject
$importSolution = Join-Path $imports 'Scope.slnx'
'<Solution><Project Path="App/App.csproj" /><Project Path="../empty-docs/Docs.csproj" /></Solution>' | Set-Content -LiteralPath $importSolution
$withDocs = Scan $importSolution @()
AssertFinding $withDocs
if (-not (HasNotice $withDocs 'no-source') -or (HasNotice $withDocs 'compilation-load')) { throw 'An empty documentation project failed the scan.' }
