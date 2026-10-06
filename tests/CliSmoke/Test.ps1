$ErrorActionPreference = 'Stop'
$root = (Resolve-Path (Join-Path $PSScriptRoot '../..')).Path
$feed = Join-Path $root 'artifacts'
$analyzerSpec = [xml](Get-Content -LiteralPath (Join-Path $root 'Dotnetarium.Analyzers/Dotnetarium.Analyzers.csproj') -Raw)
$toolSpec = [xml](Get-Content -LiteralPath (Join-Path $root 'Dotnetarium.Tool/Dotnetarium.Tool.csproj') -Raw)
$analyzerVersion = $analyzerSpec.SelectSingleNode('//PackageVersion').InnerText
$toolVersion = $toolSpec.SelectSingleNode('//Version').InnerText
if (-not (Test-Path -LiteralPath (Join-Path $feed "dotnetarium.$toolVersion.nupkg")) -or
    -not (Test-Path -LiteralPath (Join-Path $feed "Dotnetarium.Analyzers.$analyzerVersion.nupkg"))) {
    throw 'Pack both 2.x packages into artifacts before running this smoke check.'
}

$scratch = Join-Path ([System.IO.Path]::GetTempPath()) ('dotnetarium-cli-smoke-' + [guid]::NewGuid().ToString('N'))
$toolPath = Join-Path $scratch 'tool'
$projectPath = Join-Path $scratch 'project'
New-Item -ItemType Directory -Path $scratch, $toolPath, $projectPath -Force | Out-Null
$env:NUGET_PACKAGES = Join-Path $scratch 'packages'

& dotnet new classlib -n CliSmoke -o $projectPath --force --no-restore | Out-Null
if ($LASTEXITCODE -ne 0) { throw 'Could not create CLI fixture.' }
@'
using System;
using System.Diagnostics;
using System.Net.Http;
using System.Net.Security;
using System.Net.WebSockets;
using Microsoft.Extensions.Hosting;
using System.IO;
using System.IO.Pipelines;
using System.Buffers;
using System.Text;
using System.Threading.Tasks;
using System.Collections.Generic;
using Microsoft.AspNetCore.SignalR;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Routing;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.DependencyInjection;
using Dapper;
using Npgsql;
using Azure.Messaging.ServiceBus;
using Microsoft.Azure.Functions.Worker;
using Microsoft.Azure.Functions.Worker.Http;
using System.Xml;
using MassTransit;
using RabbitMQ.Client;
using RabbitMQ.Client.Events;
using Confluent.Kafka;
using Azure.Messaging;
using Azure.Messaging.EventHubs;
using Microsoft.AspNetCore.Components;
using Microsoft.AspNetCore.Components.Rendering;

public class Demo
{
    public async Task RunAsync()
    {
        var input = Console.ReadLine();
        Process.Start(input!);
        using var client = new HttpClient();
        await client.GetStringAsync(input);
        using var connection = new NpgsqlConnection();
        _ = connection.Query(input!);
        _ = new NpgsqlCommand(input);
        var settings = new Newtonsoft.Json.JsonSerializerSettings
        {
            TypeNameHandling = Newtonsoft.Json.TypeNameHandling.All
        };
        new Custom().Execute(input!);
        _ = new HttpClientHandler { ServerCertificateCustomValidationCallback = HttpClientHandler.DangerousAcceptAnyServerCertificateValidator };
        _ = new SocketsHttpHandler { SslOptions = new SslClientAuthenticationOptions { RemoteCertificateValidationCallback = (_, _, _, _) => true } };
        _ = new SslStream(new MemoryStream(), false, (_, _, _, _) => true);
        var socket = new ClientWebSocket();
        socket.Options.RemoteCertificateValidationCallback = (_, _, _, _) => true;
        _ = new HttpClientHandler { ServerCertificateCustomValidationCallback = (_, _, _, errors) => errors == SslPolicyErrors.None };
    }
}

public static class DevelopmentTls
{
    public static void Configure(IHostEnvironment environment)
    {
        if (environment.IsDevelopment())
            _ = new HttpClientHandler { ServerCertificateCustomValidationCallback = HttpClientHandler.DangerousAcceptAnyServerCertificateValidator };
    }
}
public class Custom
{
    public void Execute(string query) { }
}

public sealed class HubService { public string Command => "fixed"; }
public sealed class BodyInput { public string Command { get; set; } = ""; }
public sealed class InputHub : Hub
{
    public void Execute(string command, HubService service)
    {
        Process.Start(command);
        Process.Start(service.Command);
    }
    public async Task Upload(IAsyncEnumerable<string> stream)
    {
        await foreach (var command in stream) Process.Start(command);
    }
}
public sealed class FunctionInput
{
    [Function("http")]
    public async Task Http([HttpTrigger] HttpRequestData request,
        [Microsoft.Azure.Functions.Worker.Http.FromBody] BodyInput body)
    {
        Process.Start(await request.ReadAsStringAsync());
        Process.Start(body.Command);
        Process.Start(request.FunctionContext.InvocationId);
    }
    [Function("bus")]
    public void Bus([ServiceBusTrigger("queue")] ServiceBusReceivedMessage message,
        ServiceBusMessageActions actions, HubService service)
    {
        Process.Start(message.Body.ToString());
        Process.Start(actions.ToString());
        Process.Start(service.Command);
    }
}
public static class NetworkInput
{
    public static async Task Run(HttpContext context)
    {
        var socket = await context.WebSockets.AcceptWebSocketAsync();
        var bytes = new byte[128];
        await socket.ReceiveAsync(bytes.AsMemory(), default);
        Process.Start(Encoding.UTF8.GetString(bytes));
        var result = await context.Request.BodyReader.ReadAsync();
        Process.Start(Encoding.UTF8.GetString(result.Buffer.ToArray()));
        if (context.Request.BodyReader.TryRead(out var available))
            Process.Start(Encoding.UTF8.GetString(available.Buffer.ToArray()));
        var local = new System.IO.Pipelines.Pipe();
        var safe = await local.Reader.ReadAsync();
        Process.Start(Encoding.UTF8.GetString(safe.Buffer.ToArray()));
    }
}
public static class HubRegistration
{
    public static void Configure(IServiceCollection services)
    {
        services.AddSingleton<HubService>();
        services.AddSignalR();
    }
    public static void Map(IEndpointRouteBuilder endpoints) => endpoints.MapHub<InputHub>("/input");
    public static void MapBody(WebApplication app)
    {
        app.MapPost("/body", (BodyInput body) => Process.Start(body.Command));
        app.MapPost("/upload", (IFormFile file) => Process.Start(file.FileName));
        app.MapPost("/service", (HubService service) => Process.Start(service.Command));
    }
}

public sealed class MessageWorker : MassTransit.IConsumer<BodyInput>
{
    public Task Consume(ConsumeContext<BodyInput> context) { Process.Start(context.Message.Command); return Task.CompletedTask; }
    public static void Configure(IServiceCollection services) => services.AddMassTransit(x => x.AddConsumer<MessageWorker>());
}
public static class BrokerInputs
{
    public static void Configure(IChannel channel, Confluent.Kafka.IConsumer<string, string> kafka)
    {
        var consumer = new AsyncEventingBasicConsumer(channel);
        consumer.ReceivedAsync += (_, args) => { Process.Start(Encoding.UTF8.GetString(args.Body.Span)); return Task.CompletedTask; };
        Process.Start(kafka.Consume(default(System.Threading.CancellationToken)).Message.Value);
        Process.Start(new Confluent.Kafka.Message<string, string> { Value = "fixed" }.Value);
    }
}
public sealed class EventInputs
{
    [Function("queue")] public void Queue([QueueTrigger("queue")] string value, HubService service) { Process.Start(value); Process.Start(service.Command); }
    [Function("grid")] public void Grid([EventGridTrigger] CloudEvent value) => Process.Start(value.Data.ToString());
    [Function("hub")] public void Hub([EventHubTrigger("hub")] EventData value) => Process.Start(value.EventBody.ToString());
}
public sealed class BoundInput
{
    public string Command { get; set; } = "fixed";
    public string Fixed { get; set; } = "fixed";
    public static ValueTask<BoundInput> BindAsync(HttpContext context) => new(new BoundInput { Command = context.Request.Query["command"] });
}
public static class CustomEndpoints
{
    public static void Configure(WebApplication app)
    {
        app.MapGet("/bound", (BoundInput input) => { Process.Start(input.Command); Process.Start(input.Fixed); });
        app.MapGet("/filtered", (string input) => input).AddEndpointFilter((context, next) => { Process.Start(context.GetArgument<string>(0)); return next(context); });
    }
    public static async Task Buffer(HttpContext context)
    {
        var socket = await context.WebSockets.AcceptWebSocketAsync();
        var first = new byte[128]; var second = new byte[128]; var view = first.AsMemory(); view = second.AsMemory();
        await socket.ReceiveAsync(view, default);
        Process.Start(Encoding.UTF8.GetString(second));
        Process.Start(Encoding.UTF8.GetString(first));
    }
    public static void Xml(HttpContext context)
    {
        var settings = new XmlReaderSettings { DtdProcessing = DtdProcessing.Parse, XmlResolver = new XmlUrlResolver() };
        _ = XmlReader.Create(new StringReader(context.Request.Query["xml"]), settings);
        _ = XmlReader.Create(new StringReader(context.Request.Query["xml"]), new XmlReaderSettings { DtdProcessing = DtdProcessing.Parse });
    }
    public static async Task Validated(HttpContext context, HttpClient client)
    {
        string input = context.Request.Query["value"];
        if (input == "fixed") Process.Start(input);
        var path = Path.GetFullPath(input);
        if (path.StartsWith("/safe/", StringComparison.Ordinal)) File.ReadAllText(path);
        await client.GetStringAsync("https://example.com/items/" + input);
    }
}
public sealed class BrowserInput : ComponentBase
{
    private string value = "fixed";
    private void Changed(ChangeEventArgs args) => value = args.Value.ToString();
    protected override void BuildRenderTree(RenderTreeBuilder builder)
    {
        builder.OpenElement(0, "input");
        builder.AddAttribute(1, "onchange", EventCallback.Factory.Create<ChangeEventArgs>(this, Changed));
        builder.CloseElement();
        builder.AddMarkupContent(2, value);
        builder.AddContent(3, value);
    }
}

namespace Newtonsoft.Json
{
    public enum TypeNameHandling { None, All }
    public sealed class JsonSerializerSettings
    {
        public TypeNameHandling TypeNameHandling { get; set; }
    }
}
'@ | Set-Content -LiteralPath (Join-Path $projectPath 'Unsafe Input.cs') -Encoding utf8
$project = Join-Path $projectPath 'CliSmoke.csproj'
$projectXml = Get-Content -LiteralPath $project -Raw
$packageReference = "  <ItemGroup><FrameworkReference Include=`"Microsoft.AspNetCore.App`" /><PackageReference Include=`"Dotnetarium.Analyzers`" Version=`"$analyzerVersion`" /><PackageReference Include=`"Microsoft.Azure.Functions.Worker.Core`" Version=`"2.52.0`" /><PackageReference Include=`"Microsoft.Azure.Functions.Worker.Extensions.Http`" Version=`"3.3.0`" /><PackageReference Include=`"Microsoft.Azure.Functions.Worker.Extensions.ServiceBus`" Version=`"5.24.0`" /><PackageReference Include=`"Dapper`" Version=`"2.1.79`" /><PackageReference Include=`"Npgsql`" Version=`"10.0.3`" /></ItemGroup>"
$projectXml.Replace('</Project>', "$packageReference`n</Project>") |
    Set-Content -LiteralPath $project -Encoding utf8
$extraPackages = '<ItemGroup><PackageReference Include="MassTransit" Version="9.2.3" /><PackageReference Include="RabbitMQ.Client" Version="7.2.2" /><PackageReference Include="Confluent.Kafka" Version="2.15.1" /><PackageReference Include="Microsoft.Azure.Functions.Worker.Extensions.Storage.Queues" Version="5.5.5" /><PackageReference Include="Microsoft.Azure.Functions.Worker.Extensions.EventGrid" Version="3.6.0" /><PackageReference Include="Microsoft.Azure.Functions.Worker.Extensions.EventHubs" Version="6.5.0" /></ItemGroup>'
(Get-Content -LiteralPath $project -Raw).Replace('</Project>', "$extraPackages`n</Project>") | Set-Content -LiteralPath $project -Encoding utf8
$nugetConfig = Join-Path $scratch 'NuGet.Config'
@"
<?xml version="1.0" encoding="utf-8"?>
<configuration>
  <packageSources><clear /><add key="local" value="$feed" /><add key="nuget.org" value="https://api.nuget.org/v3/index.json" /></packageSources>
  <packageSourceMapping>
    <packageSource key="local"><package pattern="Dotnetarium*" /></packageSource>
    <packageSource key="nuget.org"><package pattern="*" /></packageSource>
  </packageSourceMapping>
</configuration>
"@ | Set-Content -LiteralPath $nugetConfig -Encoding utf8
# These sink/flow witnesses intentionally use stdin, so opt into its local scope.
'{"Version":"2.0","ThreatModels":["remote","local"]}' |
    Set-Content -LiteralPath (Join-Path $projectPath 'dotnetarium.json') -Encoding utf8
& dotnet restore $project --configfile $nugetConfig --nologo -v quiet
if ($LASTEXITCODE -ne 0) { throw 'CLI fixture restore failed.' }
$buildOutput = & dotnet build $project --no-restore --nologo -v quiet -p:UseSharedCompilation=false 2>&1
if ($LASTEXITCODE -ne 0 -or -not ($buildOutput -match 'DNA0001') -or -not ($buildOutput -match 'DNA0002') -or
    -not ($buildOutput -match 'DNA0008') -or -not ($buildOutput -match 'DNA0011') -or -not ($buildOutput -match 'DNA0020')) {
    $buildOutput | Write-Output
    throw 'Packaged analyzer did not report the expected .NET 10 findings.'
}

& dotnet tool install dotnetarium --version $toolVersion --tool-path $toolPath --configfile $nugetConfig --ignore-failed-sources --no-cache
if ($LASTEXITCODE -ne 0) { throw 'Local global tool install failed.' }
$tool = Join-Path $toolPath $(if ($IsWindows) { 'dotnetarium.exe' } else { 'dotnetarium' })
$help = & $tool --help
if ($LASTEXITCODE -ne 0 -or -not ($help -match '\.slnx') -or -not ($help -match '--sarif') -or
    -not ($help -match '--fail\b') -or
    ($help -match '--sdk-path|--sarif-absolute-paths|--cwe|--export|--fail-any-warn|--fail-on-findings')) {
    throw 'CLI help does not match the simplified options.'
}
$sarif = Join-Path $scratch 'results.sarif'
$launcher = Join-Path $scratch 'launcher'
New-Item -ItemType Directory -Path $launcher | Out-Null
'{"sdk":{"version":"8.0.100","rollForward":"disable"}}' |
    Set-Content -LiteralPath (Join-Path $launcher 'global.json') -Encoding utf8
Push-Location $launcher
try {
    $scanOutput = & $tool $project --sarif $sarif --fail
    $scanExitCode = $LASTEXITCODE
} finally {
    Pop-Location
}
if ($scanExitCode -ne 1) { throw 'CLI did not scan from a directory with a different SDK pin.' }
if (-not ($scanOutput -match 'CWE-')) { throw 'Console findings omitted default CWE groups.' }
$report = Get-Content -LiteralPath $sarif -Raw | ConvertFrom-Json
$ids = @($report.runs[0].results | ForEach-Object ruleId)
if (@($ids | Where-Object { $_ -eq 'DNA0001' }).Count -ne 2 -or
    @($ids | Where-Object { $_ -eq 'DNA0002' }).Count -ne 20 -or
    @($ids | Where-Object { $_ -eq 'DNA0003' }).Count -ne 1 -or
    @($ids | Where-Object { $_ -eq 'DNA0008' }).Count -ne 1 -or
    @($ids | Where-Object { $_ -eq 'DNA0011' }).Count -ne 1 -or
    @($ids | Where-Object { $_ -eq 'DNA0020' }).Count -ne 4 -or
    @($ids | Where-Object { $_ -eq 'DNA0021' }).Count -ne 1) {
    throw ('Unexpected default CLI rules: ' + ($ids -join ', '))
}
foreach ($result in $report.runs[0].results) {
    if ($result.locations[0].physicalLocation.artifactLocation.uri -ne 'Unsafe%20Input.cs' -or
        $result.locations[0].physicalLocation.artifactLocation.uriBaseId -ne '%SRCROOT%' -or
        $result.PSObject.Properties.Name -contains 'relatedLocations' -or
        ($result.ruleId -notin @('DNA0008', 'DNA0020') -and @($result.codeFlows).Count -ne 1)) {
        throw ('Invalid relative path or engine flow for ' + $result.ruleId)
    }
    if ($report.runs[0].tool.driver.rules[$result.ruleIndex].id -ne $result.ruleId) {
        throw ('Finding does not reference its rule definition: ' + $result.ruleId)
    }
}
$ruleIds = @($report.runs[0].tool.driver.rules | ForEach-Object id)
$tlsRules = @($report.runs[0].tool.driver.rules | Where-Object id -eq 'DNA0020')
if ($tlsRules.Count -ne 1 -or $tlsRules[0].defaultConfiguration.level -ne 'warning' -or
    $tlsRules[0].properties.tags -notcontains 'CWE-295') {
    throw 'TLS configuration findings must reference one warning rule with CWE-295 metadata.'
}
$xmlRules = @($report.runs[0].tool.driver.rules | Where-Object id -eq 'DNA0021')
if ($xmlRules.Count -ne 1 -or $xmlRules[0].defaultConfiguration.level -ne 'warning' -or
    $xmlRules[0].properties.tags -notcontains 'CWE-611') {
    throw 'XXE findings must reference one warning rule with CWE-611 metadata.'
}
foreach ($result in @($report.runs[0].results | Where-Object ruleId -eq 'DNA0020')) {
    if ($result.PSObject.Properties.Name -contains 'codeFlows') {
        throw 'A TLS configuration finding must not invent a source-to-sink flow.'
    }
}
if (@($ruleIds | Sort-Object -Unique).Count -ne $ruleIds.Count) {
    throw 'SARIF repeats a rule definition.'
}
$flow = @($report.runs[0].results | Where-Object ruleId -eq 'DNA0001')[0].codeFlows[0].threadFlows[0].locations
if ($flow.Count -lt 2 -or $flow[0].location.id -ne 1 -or
    $flow[-1].location.physicalLocation.artifactLocation.uri -ne 'Unsafe%20Input.cs') {
    throw 'SARIF flow steps are missing stable locations.'
}

# The same analyzer package and .NET 10-hosted tool must also scan .NET 8 code.
$projectXml = Get-Content -LiteralPath $project -Raw
$projectXml.Replace('<TargetFramework>net10.0</TargetFramework>',
    '<TargetFramework>net8.0</TargetFramework>') |
    Set-Content -LiteralPath $project -Encoding utf8
& dotnet restore $project --configfile $nugetConfig --nologo -v quiet
if ($LASTEXITCODE -ne 0) { throw '.NET 8 fixture restore failed.' }
$buildOutput = & dotnet build $project --no-restore --nologo -v quiet -p:UseSharedCompilation=false 2>&1
if ($LASTEXITCODE -ne 0 -or -not ($buildOutput -match 'DNA0001') -or -not ($buildOutput -match 'DNA0002') -or
    -not ($buildOutput -match 'DNA0008') -or -not ($buildOutput -match 'DNA0011') -or -not ($buildOutput -match 'DNA0020')) {
    $buildOutput | Write-Output
    throw 'Packaged analyzer did not report the expected .NET 8 findings.'
}
$net8Sarif = Join-Path $scratch 'results-net8.sarif'
& $tool $project --sarif $net8Sarif --fail | Out-Null
if ($LASTEXITCODE -ne 1) { throw 'Global tool did not find the .NET 8 flows.' }
$net8Report = Get-Content -LiteralPath $net8Sarif -Raw | ConvertFrom-Json
$net8Ids = @($net8Report.runs[0].results | ForEach-Object ruleId)
if (Compare-Object ($ids | Sort-Object) ($net8Ids | Sort-Object)) {
    throw '.NET 8 and .NET 10 fixtures must report the same source-to-sink flows.'
}

$config = Join-Path $scratch 'custom.json'
@'
{
  "Version": "2.0",
  "ThreatModels": [ "remote", "local" ],
  "Sinks": [
    {
      "Type": "Custom",
      "TaintTypes": ["SqlInjection"],
      "Methods": [{ "Name": "Execute", "Arguments": ["query"] }]
    }
  ]
}
'@ | Set-Content -LiteralPath $config -Encoding utf8
Copy-Item -LiteralPath $config -Destination (Join-Path $projectPath 'dotnetarium.json')
$configuredBuild = & dotnet build $project --no-restore --nologo -v quiet -p:UseSharedCompilation=false 2>&1
if ($LASTEXITCODE -ne 0 -or ([regex]::Matches(($configuredBuild -join "`n"), 'DNA0001')).Count -lt 3) {
    $configuredBuild | Write-Output
    throw 'Packaged analyzer did not include lowercase dotnetarium.json automatically.'
}
$customOutput = & $tool $project
if ($LASTEXITCODE -ne 0 -or ([regex]::Matches(($customOutput -join "`n"), 'DNA0001')).Count -ne 3) {
    throw 'CLI did not discover lowercase dotnetarium.json.'
}
$override = Join-Path $scratch 'override.json'
'{"Version":"2.0","ThreatModels":["remote","local"],"Sinks":[]}' | Set-Content -LiteralPath $override -Encoding utf8
$overrideOutput = & $tool $project --config $override
if ($LASTEXITCODE -ne 0 -or ([regex]::Matches(($overrideOutput -join "`n"), 'DNA0001')).Count -ne 2) {
    throw 'Explicit --config did not override the project config.'
}

$bad = Join-Path $scratch 'bad.json'
'{"Version":"2.0","Sinkz":[]}' | Set-Content -LiteralPath $bad -Encoding utf8
$badOutput = & $tool $project --config $bad 2>&1
if ($LASTEXITCODE -ne 2 -or -not ($badOutput -match 'Invalid dotnetarium.json')) {
    throw 'CLI did not reject an invalid JSON rule field.'
}

# Test metadata suppresses only certificate bypasses, for both the package and CLI.
$applicationProjectXml = Get-Content -LiteralPath $project -Raw
$testProjectXml = $applicationProjectXml.Replace('</Project>', '<PropertyGroup><IsTestProject>true</IsTestProject></PropertyGroup></Project>')
$testProjectXml | Set-Content -LiteralPath $project -Encoding utf8
$testBuild = & dotnet build $project --no-restore --nologo -v quiet -p:UseSharedCompilation=false 2>&1
if ($LASTEXITCODE -ne 0 -or ($testBuild -match 'DNA0020') -or -not ($testBuild -match 'DNA0001')) {
    $testBuild | Write-Output
    throw 'Analyzer package did not honor test-project metadata while preserving other rules.'
}
$testOutput = & $tool $project
if ($LASTEXITCODE -ne 0 -or ($testOutput -match 'DNA0020') -or -not ($testOutput -match 'DNA0001')) {
    throw 'CLI did not honor test-project metadata while preserving other rules.'
}
$globalConfig = Join-Path $projectPath '.globalconfig'
"is_global = true`ndotnetarium_analyze_test_certificates = true" | Set-Content -LiteralPath $globalConfig -Encoding utf8
$testOptInOutput = & $tool $project
if ($LASTEXITCODE -ne 0 -or ([regex]::Matches(($testOptInOutput -join "`n"), 'DNA0020')).Count -ne 4) {
    throw 'Test-project certificate opt-in did not restore CLI findings.'
}
Remove-Item -LiteralPath $globalConfig -Force

# The tool must also read evaluated metadata without our NuGet props present.
$testProjectXml.Replace("<PackageReference Include=`"Dotnetarium.Analyzers`" Version=`"$analyzerVersion`" />", '') |
    Set-Content -LiteralPath $project -Encoding utf8
& dotnet restore $project --configfile $nugetConfig --nologo -v quiet
if ($LASTEXITCODE -ne 0) { throw 'Standalone CLI test fixture restore failed.' }
$standaloneTestOutput = & $tool $project
if ($LASTEXITCODE -ne 0 -or ($standaloneTestOutput -match 'DNA0020') -or -not ($standaloneTestOutput -match 'DNA0001')) {
    $standaloneTestOutput | Write-Output
    throw 'Standalone CLI did not read evaluated test-project metadata.'
}
$applicationProjectXml | Set-Content -LiteralPath $project -Encoding utf8
& dotnet restore $project --configfile $nugetConfig --nologo -v quiet
if ($LASTEXITCODE -ne 0) { throw 'Application fixture restore failed.' }

Add-Content -LiteralPath (Join-Path $projectPath 'Unsafe Input.cs') -Value 'class Broken { MissingType value; }'
$incompleteSarif = Join-Path $scratch 'incomplete.sarif'
$invalidProjectOutput = & $tool $project --sarif $incompleteSarif 2>&1
if ($LASTEXITCODE -ne 2 -or -not ($invalidProjectOutput -match 'CS0246') -or
    -not ($invalidProjectOutput -match 'Scan incomplete') -or
    -not (Test-Path -LiteralPath $incompleteSarif)) {
    throw 'CLI did not explain incomplete scanning of a project with compiler errors.'
}
$incompleteReport = Get-Content -LiteralPath $incompleteSarif -Raw | ConvertFrom-Json
if ($incompleteReport.runs[0].invocations[0].executionSuccessful -ne $false -or
    $incompleteReport.runs[0].invocations[0].properties.'dotnetarium.coverage' -ne 'partial' -or
    -not @($incompleteReport.runs[0].invocations[0].toolExecutionNotifications |
        Where-Object { $_.descriptor.id -eq 'compiler-error' }).Count -or
    -not @($incompleteReport.runs[0].results).Count) {
    throw 'Incomplete SARIF must retain findings and identify failed semantic coverage.'
}

# A bounded recursive root must not prevent ordinary findings or direct rules.
$budgetRoot = Join-Path $scratch 'budget'
New-Item -ItemType Directory -Path $budgetRoot | Out-Null
$budgetProject = Join-Path $budgetRoot 'Budget.csproj'
'<Project Sdk="Microsoft.NET.Sdk"><PropertyGroup><TargetFramework>net10.0</TargetFramework></PropertyGroup></Project>' |
    Set-Content -LiteralPath $budgetProject
@'
using System;
using System.Diagnostics;
using System.Security.Cryptography;
public static class Demo {
    static string Walk(string input, int count) {
        if (count > 0) { input = Walk(input, count - 1); input = Walk(input, count - 1); }
        return input;
    }
    public static void Expensive(int count) => Process.Start(Walk(Console.ReadLine(), count));
    public static void Ordinary() => Process.Start(Console.ReadLine());
    public static void Crypto() { using var aes = Aes.Create(); aes.Mode = CipherMode.ECB; }
}
'@ | Set-Content -LiteralPath (Join-Path $budgetRoot 'Demo.cs')
'{"Version":"2.0","ThreatModels":["remote","local"],"MaxTaintAnalysisWork":1000}' |
    Set-Content -LiteralPath (Join-Path $budgetRoot 'dotnetarium.json')
& dotnet restore $budgetProject --configfile $nugetConfig --nologo -v quiet
if ($LASTEXITCODE -ne 0) { throw 'Budget fixture restore failed.' }
$budgetSarif = Join-Path $scratch 'budget.sarif'
foreach ($failFlag in @($false, $true)) {
    $scanArguments = @($budgetProject, '--sarif', $budgetSarif)
    if ($failFlag) { $scanArguments += '--fail' }
    $budgetOutput = & $tool @scanArguments 2>&1
    if ($LASTEXITCODE -ne 2) { throw 'A budget cutoff must return incomplete exit code 2, including with --fail.' }
    $budgetReport = Get-Content -LiteralPath $budgetSarif -Raw | ConvertFrom-Json
    $budgetFindings = @($budgetReport.runs[0].results)
    $budgetNotices = @($budgetReport.runs[0].invocations[0].toolExecutionNotifications |
        Where-Object { $_.descriptor.id -eq 'analysis-budget' })
    if ($budgetFindings.Count -ne 2 -or
        @($budgetFindings | Where-Object ruleId -eq 'DNA0002').Count -ne 1 -or
        @($budgetFindings | Where-Object ruleId -eq 'DNA0014').Count -ne 1 -or
        -not ($budgetNotices.message.text -match 'Demo.Expensive') -or
        -not (@($budgetFindings | Where-Object ruleId -eq 'DNA0002')[0].message.text -match 'Ordinary') -or
        $budgetReport.runs[0].invocations[0].executionSuccessful -ne $false -or
        $budgetReport.runs[0].invocations[0].properties.'dotnetarium.coverage' -ne 'partial' -or
        @($budgetReport.runs[0].tool.driver.rules | Where-Object id -eq 'DNA9000').Count) {
        throw 'Budget handling lost independent findings or exposed a coverage notice as a security rule.'
    }
}

# Use real EF Core assemblies: exclude migration bodies, retain direct secrets,
# and continue scanning ordinary callers. Also check the packaged analyzer.
$migrationRoot = Join-Path $scratch 'migration'
New-Item -ItemType Directory -Path $migrationRoot | Out-Null
$migrationProject = Join-Path $migrationRoot 'Migration.csproj'
'{"Version":"2.0","ThreatModels":["remote","local"]}' |
    Set-Content -LiteralPath (Join-Path $migrationRoot 'dotnetarium.json') -Encoding utf8
@"
<Project Sdk="Microsoft.NET.Sdk"><PropertyGroup><TargetFramework>net10.0</TargetFramework></PropertyGroup>
<ItemGroup><PackageReference Include="Microsoft.EntityFrameworkCore.Relational" Version="10.0.12" />
<PackageReference Include="Dotnetarium.Analyzers" Version="$analyzerVersion" /></ItemGroup></Project>
"@ | Set-Content -LiteralPath $migrationProject
@'
using System;
using System.Diagnostics;
using System.Net;
using Microsoft.EntityFrameworkCore.Migrations;
public class Seed : Migration {
    protected override void Up(MigrationBuilder builder) {
        Process.Start(Console.ReadLine());
        _ = new NetworkCredential("seed", "secret-production-password");
    }
    protected override void Down(MigrationBuilder builder) { }
    public static void Run() => Process.Start(Console.ReadLine());
}
public class Outside {
    public static void Run() { Seed.Run(); Process.Start(Console.ReadLine()); }
}
'@ | Set-Content -LiteralPath (Join-Path $migrationRoot 'Seed.cs')
@'
// <auto-generated />
using System;
using System.Diagnostics;
using System.Net;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Infrastructure;
public class Schema : ModelSnapshot {
    protected override void BuildModel(ModelBuilder builder) {
        Process.Start(Console.ReadLine());
        _ = new NetworkCredential("snapshot", "secret-production-password");
    }
}
'@ | Set-Content -LiteralPath (Join-Path $migrationRoot 'Schema.Designer.cs')
& dotnet restore $migrationProject --configfile $nugetConfig --nologo -v quiet
if ($LASTEXITCODE -ne 0) { throw 'Migration fixture restore failed.' }
$migrationBuild = & dotnet build $migrationProject --no-restore --nologo -v quiet -p:UseSharedCompilation=false 2>&1
if ($LASTEXITCODE -ne 0 -or
    @($migrationBuild | Where-Object { $_ -match 'warning DNA0002' } | Sort-Object -Unique).Count -ne 1 -or
    @($migrationBuild | Where-Object { $_ -match 'warning DNA0009' } | Sort-Object -Unique).Count -ne 2 -or
    ($migrationBuild -match 'DNA9000|AD0001')) {
    $migrationBuild | Write-Output
    throw 'Packaged analyzer migration exclusion or direct secrets regressed.'
}
$migrationSarif = Join-Path $scratch 'migration.sarif'
& $tool $migrationProject --sarif $migrationSarif --fail | Out-Null
if ($LASTEXITCODE -ne 1) { throw 'Migration CLI fixture must report ordinary findings.' }
$migrationReport = Get-Content -LiteralPath $migrationSarif -Raw | ConvertFrom-Json
if (@($migrationReport.runs[0].results).Count -ne 3 -or
    @($migrationReport.runs[0].results | Where-Object ruleId -eq 'DNA0002').Count -ne 1 -or
    @($migrationReport.runs[0].results | Where-Object ruleId -eq 'DNA0009').Count -ne 2 -or
    $migrationReport.runs[0].invocations[0].properties.'dotnetarium.coverage' -ne 'complete') {
    throw 'CLI migration fixture must retain two literal secrets and one ordinary command finding.'
}

$scopeRoot = Join-Path $scratch 'scope'
New-Item -ItemType Directory -Path $scopeRoot | Out-Null
$scopeProject = Join-Path $scopeRoot 'Scope.csproj'
@"
<Project Sdk="Microsoft.NET.Sdk">
  <PropertyGroup><TargetFramework>net10.0</TargetFramework></PropertyGroup>
  <ItemGroup><FrameworkReference Include="Microsoft.AspNetCore.App" /><PackageReference Include="Dotnetarium.Analyzers" Version="$analyzerVersion" /></ItemGroup>
</Project>
"@ | Set-Content -LiteralPath $scopeProject -Encoding utf8
@'
using System;
using System.Diagnostics;
using Microsoft.AspNetCore.Http;
public class Origins {
    public void Remote(HttpRequest request) => Process.Start(request.Query["command"].ToString());
    public void Stdin() => Process.Start(Console.ReadLine());
    public void EnvironmentInput() => Process.Start(Environment.GetEnvironmentVariable("COMMAND"));
}
'@ | Set-Content -LiteralPath (Join-Path $scopeRoot 'Origins.cs') -Encoding utf8
& dotnet restore $scopeProject --configfile $nugetConfig --nologo -v quiet
if ($LASTEXITCODE -ne 0) { throw 'Scope fixture restore failed.' }
$scopeConfig = Join-Path $scopeRoot 'dotnetarium.json'
foreach ($scope in @(
    @{ Name = 'default'; Selection = $null; Count = 1 },
    @{ Name = 'local'; Selection = @('local'); Count = 2 },
    @{ Name = 'both'; Selection = @('remote', 'local'); Count = 3 }
)) {
    if ($null -eq $scope.Selection) {
        if (Test-Path -LiteralPath $scopeConfig) { Remove-Item -LiteralPath $scopeConfig }
    } else {
        @{ Version = '2.0'; ThreatModels = $scope.Selection } | ConvertTo-Json |
            Set-Content -LiteralPath $scopeConfig -Encoding utf8
    }
    $scopeBuild = & dotnet build $scopeProject --no-restore --nologo -v quiet -t:Rebuild -p:UseSharedCompilation=false 2>&1
    if ($LASTEXITCODE -ne 0 -or ($scopeBuild -match 'DNA9000|AD0001') -or
        @($scopeBuild | Where-Object { $_ -match 'warning DNA0002' } | Sort-Object -Unique).Count -ne $scope.Count) {
        $scopeBuild | Write-Output
        throw "Packaged analyzer source selection failed: $($scope.Name)"
    }
    $scopeSarif = Join-Path $scopeRoot "$($scope.Name).sarif"
    & $tool $scopeProject --sarif $scopeSarif --fail | Out-Null
    if ($LASTEXITCODE -ne 1) { throw "CLI scope scan failed: $($scope.Name)" }
    $scopeReport = Get-Content -LiteralPath $scopeSarif -Raw | ConvertFrom-Json
    if (@($scopeReport.runs[0].results | Where-Object ruleId -eq 'DNA0002').Count -ne $scope.Count -or
        $scopeReport.runs[0].invocations[0].properties.'dotnetarium.coverage' -ne 'complete') {
        throw "CLI and analyzer source selections disagree: $($scope.Name)"
    }
}
$scopeOverride = Join-Path $scopeRoot 'remote.json'
'{"Version":"2.0","ThreatModels":["remote"]}' | Set-Content -LiteralPath $scopeOverride -Encoding utf8
$scopeOverrideSarif = Join-Path $scopeRoot 'override.sarif'
& $tool $scopeProject --config $scopeOverride --sarif $scopeOverrideSarif --fail | Out-Null
if ($LASTEXITCODE -ne 1 -or @((Get-Content -LiteralPath $scopeOverrideSarif -Raw | ConvertFrom-Json).runs[0].results).Count -ne 1) {
    throw 'Explicit CLI configuration did not replace project source selection.'
}

. (Join-Path $PSScriptRoot 'Test-Profiles.ps1')
'Analyzer NuGet package and global tool scan .NET 8/10; source selection, custom JSON, relative SARIF, and compiler error checks passed.' | Write-Output
exit 0
