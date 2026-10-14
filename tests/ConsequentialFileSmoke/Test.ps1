param([string]$ToolDll)
$ErrorActionPreference = 'Stop'
$root = (Resolve-Path (Join-Path $PSScriptRoot '../..')).Path
if (-not $ToolDll) { $ToolDll = Join-Path $root 'Dotnetarium.Tool/bin/Release/net10.0/Dotnetarium.Tool.dll' }
$spec = [xml](Get-Content -Raw -LiteralPath (Join-Path $root 'Dotnetarium.Analyzers/Dotnetarium.Analyzers.csproj'))
$version = $spec.SelectSingleNode('//PackageVersion').InnerText
$scratch = Join-Path ([IO.Path]::GetTempPath()) ('dotnetarium-files-' + [guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $scratch | Out-Null
$previousPackages = $env:NUGET_PACKAGES
try {
    $env:NUGET_PACKAGES = Join-Path $scratch 'packages'
    $nugetConfig = Join-Path $scratch 'NuGet.Config'
    @"
<configuration><packageSources><clear />
<add key="fixture" value="$([System.Security.SecurityElement]::Escape((Join-Path $root 'artifacts')))" />
<add key="nuget.org" value="https://api.nuget.org/v3/index.json" />
</packageSources></configuration>
"@ | Set-Content -LiteralPath $nugetConfig
    foreach ($framework in @('net8.0', 'net10.0')) {
        $directory = Join-Path $scratch $framework
        New-Item -ItemType Directory -Path $directory | Out-Null
        $project = Join-Path $directory 'FileAccess.csproj'
        @"
<Project Sdk="Microsoft.NET.Sdk">
<PropertyGroup><TargetFramework>$framework</TargetFramework></PropertyGroup>
<ItemGroup><FrameworkReference Include="Microsoft.AspNetCore.App" />
<PackageReference Include="Dotnetarium.Analyzers" Version="$version" /></ItemGroup>
</Project>
"@ | Set-Content -LiteralPath $project
        $source = @'
using System;
using System.IO;
using System.Formats.Tar;
using System.IO.Compression;
using System.Runtime.Loader;
using System.Runtime.InteropServices;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Http;
public class FileController : ControllerBase {
    public void Read(string path) { new FileInfo(path).OpenRead(); } // FIND
    public void Delete(string path) { new DirectoryInfo(path).Delete(true); } // FIND
    public void Move(string path) { var file = new FileInfo(path); var alias = file; file.MoveTo("fixed"); alias.Delete(); } // FIND
    public void Load(string path) { AssemblyLoadContext.Default.LoadFromAssemblyPath(path); } // FIND
    public void Native(string path) { NativeLibrary.Load(path); } // FIND
    public void Zip(string path) { ZipFile.OpenRead(path); } // FIND
    public void Tar(string path) { ((TarEntry)null).ExtractToFile(path, true); } // FIND
    public IActionResult Download(string path) => PhysicalFile(path, "application/octet-stream"); // FIND
    public IResult Minimal(string path) => Results.File(path, "application/octet-stream"); // FIND
    public void Listing(string path) { foreach (var file in Directory.EnumerateFiles(path)) System.IO.File.Delete(file); } // FIND
    public void Metadata(string path) { _ = new FileInfo(path).Exists; new DirectoryInfo(path); Directory.CreateDirectory(path); Directory.GetFiles(path); }
    public void Identity(string name) { System.Reflection.Assembly.Load(name); NativeLibrary.Load(name, typeof(FileController).Assembly, null); }
    public IResult Bytes(string value) => Results.File(System.Text.Encoding.UTF8.GetBytes(value), "application/octet-stream");
    public void ContainedArchive(Stream archive) { ZipFile.ExtractToDirectory(archive, "/output"); TarFile.ExtractToDirectory(archive, "/output", true); }
}
'@
        $source | Set-Content -LiteralPath (Join-Path $directory 'FileAccess.cs')
        $expectedLines = @($source -split "`n" | ForEach-Object -Begin { $line = 0 } -Process {
            $line++; if ($_ -match '// FIND') { $line }
        })
        & dotnet restore $project --configfile $nugetConfig --nologo -v quiet | Out-Null
        if ($LASTEXITCODE -ne 0) { throw "Restore failed: $framework" }
        $compilerSarif = Join-Path $directory 'compiler.sarif'
        & dotnet build $project --no-restore --nologo -v quiet "-p:ErrorLog=$compilerSarif" | Out-Null
        if ($LASTEXITCODE -ne 0) { throw "Analyzer build failed: $framework" }
        $reports = @($compilerSarif)
        foreach ($mode in @('project', 'no-build')) {
            $report = Join-Path $directory "$mode.sarif"
            $arguments = @($ToolDll, $project, '--sarif', $report, '--fail')
            if ($mode -eq 'no-build') { $arguments += '-nb' }
            & dotnet @arguments | Out-Null
            if ($LASTEXITCODE -ne 1) { throw "CLI exit mismatch: $framework/$mode" }
            $reports += $report
        }
        foreach ($report in $reports) {
            $run = (Get-Content -Raw -LiteralPath $report | ConvertFrom-Json).runs[0]
            if (@($run.results | Where-Object { $_.ruleId -in @('AD0001', 'DNA9000') }).Count) {
                throw "Analyzer failure or cutoff: $report"
            }
            $actualLines = @($run.results | Where-Object ruleId -eq 'DNA0004' | ForEach-Object {
                if ($_.locations[0].resultFile) { $_.locations[0].resultFile.region.startLine }
                else { $_.locations[0].physicalLocation.region.startLine }
            } | Sort-Object)
            if (($actualLines -join ',') -ne (($expectedLines | Sort-Object) -join ',')) {
                throw "File-access locations mismatch: $report ($($actualLines -join ','))"
            }
        }
        "PASS ${framework}: analyzer and both CLI modes agree on consequential accesses and safe controls"
    }
    "File-access reports: $scratch"
} finally { $env:NUGET_PACKAGES = $previousPackages }
exit 0
