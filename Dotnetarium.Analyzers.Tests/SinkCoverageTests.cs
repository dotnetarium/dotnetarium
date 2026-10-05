using System.Collections.Immutable;
using Dotnetarium.Analyzers.Cookies;
using Dotnetarium.Analyzers.Taint;
using Dotnetarium.Config;
using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.CSharp;
using Microsoft.CodeAnalysis.Diagnostics;

namespace Dotnetarium.Analyzers.Tests;

public sealed partial class SinkCoverageTests
{
    private sealed record SinkProbe(string Type, string Rule, string Statement, bool Hardcoded = false);

    // One compiled source-to-sink witness for every built-in sink type. The
    // separate member test below prevents a new method/property from silently
    // inheriting this type-level coverage without a corresponding witness.
    private static readonly SinkProbe[] Probes =
    [
        new("System.Xml.XmlReader", "DNA0021", "_ = System.Xml.XmlReader.Create(new System.IO.StringReader(input), new System.Xml.XmlReaderSettings { DtdProcessing = System.Xml.DtdProcessing.Parse, XmlResolver = new System.Xml.XmlUrlResolver() });"),
        new("System.Xml.XmlDocument", "DNA0021", "new System.Xml.XmlDocument { XmlResolver = new System.Xml.XmlUrlResolver() }.LoadXml(input);"),
        new("System.Xml.XmlTextReader", "DNA0021", "var reader = new System.Xml.XmlTextReader(new System.IO.StringReader(input)) { DtdProcessing = System.Xml.DtdProcessing.Parse, XmlResolver = new System.Xml.XmlUrlResolver() }; reader.Read();"),
        new("System.Net.NetworkCredential", "DNA0009", "_ = new System.Net.NetworkCredential(\"user\", \"secret\");", true),
        new("System.UriBuilder", "DNA0009", "_ = new System.UriBuilder { Password = \"secret\" };", true),
        new("System.Security.Cryptography.SymmetricAlgorithm", "DNA0009", "System.Security.Cryptography.Aes.Create().Key = new byte[32];", true),
        new("System.Security.Cryptography.AesGcm", "DNA0009", "_ = new System.Security.Cryptography.AesGcm(new byte[32], 16);", true),
        new("System.Security.Cryptography.AesCcm", "DNA0009", "_ = new System.Security.Cryptography.AesCcm(new byte[32]);", true),
        new("System.Security.Cryptography.ChaCha20Poly1305", "DNA0009", "_ = new System.Security.Cryptography.ChaCha20Poly1305(new byte[32]);", true),
        new("Org.BouncyCastle.Crypto.Parameters.KeyParameter", "DNA0009", "_ = new Org.BouncyCastle.Crypto.Parameters.KeyParameter(new byte[32]);", true),
        new("NSec.Cryptography.Key", "DNA0009", "_ = NSec.Cryptography.Key.Import(NSec.Cryptography.AeadAlgorithm.Aes256Gcm, new byte[32], NSec.Cryptography.KeyBlobFormat.RawSymmetricKey);", true),
        new("Sodium.SecretBox", "DNA0009", "_ = Sodium.SecretBox.Create(new byte[1], new byte[24], new byte[32]);", true),
        new("Sodium.SecretAeadAes", "DNA0009", "_ = Sodium.SecretAeadAes.Encrypt(new byte[1], new byte[12], new byte[32], null);", true),
        new("Sodium.SecretAeadChaCha20Poly1305", "DNA0009", "_ = Sodium.SecretAeadChaCha20Poly1305.Encrypt(new byte[1], new byte[8], new byte[32], null);", true),
        new("Sodium.SecretAeadChaCha20Poly1305IETF", "DNA0009", "_ = Sodium.SecretAeadChaCha20Poly1305IETF.Encrypt(new byte[1], new byte[12], new byte[32], null);", true),
        new("Sodium.SecretAeadXChaCha20Poly1305", "DNA0009", "_ = Sodium.SecretAeadXChaCha20Poly1305.Encrypt(new byte[1], new byte[24], new byte[32], null);", true),
        new("System.Diagnostics.Process", "DNA0002", "_ = System.Diagnostics.Process.Start(input);"),
        new("System.Diagnostics.ProcessStartInfo", "DNA0002", "_ = new System.Diagnostics.ProcessStartInfo { FileName = input };"),
        new("System.DirectoryServices.DirectorySearcher", "DNA0006", "_ = new System.DirectoryServices.DirectorySearcher(input);"),
        new("System.DirectoryServices.DirectoryEntry", "DNA0006", "_ = new System.DirectoryServices.DirectoryEntry(input);"),
        new("Microsoft.AspNetCore.Http.HttpResponse", "DNA0005", "new Microsoft.AspNetCore.Http.DefaultHttpContext().Response.Redirect(input);"),
        new("Microsoft.AspNetCore.Authentication.AuthenticationProperties", "DNA0005", "new Microsoft.AspNetCore.Authentication.AuthenticationProperties().RedirectUri = input;"),
        new("Microsoft.AspNetCore.Mvc.ControllerBase", "DNA0005", "_ = Redirect(input);"),
        new("Microsoft.AspNetCore.Mvc.RazorPages.PageModel", "DNA0005", "_ = new TestPage().DoRedirect(input);"),
        new("Microsoft.AspNetCore.Mvc.RedirectResult", "DNA0005", "_ = new Microsoft.AspNetCore.Mvc.RedirectResult(input);"),
        new("Microsoft.AspNetCore.Http.Results", "DNA0005", "_ = Microsoft.AspNetCore.Http.Results.Redirect(input);"),
        new("Microsoft.AspNetCore.Http.TypedResults", "DNA0005", "_ = Microsoft.AspNetCore.Http.TypedResults.Redirect(input);"),
        new("System.IO.Directory", "DNA0004", "_ = System.IO.Directory.CreateDirectory(input);"),
        new("System.IO.File", "DNA0004", "_ = System.IO.File.OpenRead(input);"),
        new("System.IO.FileInfo", "DNA0004", "_ = new System.IO.FileInfo(input);"),
        new("System.Reflection.Assembly", "DNA0004", "_ = System.Reflection.Assembly.LoadFrom(input);"),
        new("System.IO.StreamReader", "DNA0004", "_ = new System.IO.StreamReader(input);"),
        new("System.IO.StreamWriter", "DNA0004", "_ = new System.IO.StreamWriter(input);"),
        new("System.IO.FileStream", "DNA0004", "_ = new System.IO.FileStream(input, System.IO.FileMode.OpenOrCreate);"),
        new("Microsoft.AspNetCore.Mvc.PhysicalFileResult", "DNA0004", "_ = new Microsoft.AspNetCore.Mvc.PhysicalFileResult(input, \"text/plain\");"),
        new("Microsoft.AspNetCore.Mvc.RazorPages.PageModel", "DNA0004", "_ = new TestPage().PhysicalFile(input, \"text/plain\");"),
        new("System.IO.Compression.ZipFileExtensions", "DNA0004", "var zip = new System.IO.Compression.ZipArchive(new System.IO.MemoryStream(), System.IO.Compression.ZipArchiveMode.Create); System.IO.Compression.ZipFileExtensions.ExtractToFile(zip.CreateEntry(\"entry\"), input);"),
        new("SharpCompress.Archives.IArchiveEntryExtensions", "DNA0004", "SharpCompress.Archives.IArchiveEntryExtensions.WriteToFile((SharpCompress.Archives.IArchiveEntry)null!, input);"),
        new("SharpCompress.Readers.IReaderExtensions", "DNA0004", "SharpCompress.Readers.IReaderExtensions.WriteEntryToFile((SharpCompress.Readers.IReader)null!, input);"),
        new("SharpCompress.Readers.IAsyncReaderExtensions", "DNA0004", "_ = SharpCompress.Readers.IAsyncReaderExtensions.WriteEntryToFileAsync((SharpCompress.Readers.IAsyncReader)null!, input);"),
        new("Microsoft.AspNetCore.Html.HtmlString", "DNA0003", "_ = new Microsoft.AspNetCore.Html.HtmlString(input);"),
        new("Microsoft.AspNetCore.Html.IHtmlContentBuilder", "DNA0003", "_ = ((Microsoft.AspNetCore.Html.IHtmlContentBuilder)new Microsoft.AspNetCore.Html.HtmlContentBuilder()).AppendHtml(input);"),
        new("Microsoft.AspNetCore.Components.Rendering.RenderTreeBuilder", "DNA0003", "new Microsoft.AspNetCore.Components.Rendering.RenderTreeBuilder().AddMarkupContent(0, input);"),
        new("Microsoft.AspNetCore.Mvc.Rendering.IHtmlHelper", "DNA0003", "_ = ((Microsoft.AspNetCore.Mvc.Rendering.IHtmlHelper)null!).Raw(input);"),
        new("System.Xml.XmlNode", "DNA0007", "_ = new System.Xml.XmlDocument().SelectSingleNode(input);"),
        new("System.Xml.XPath.XPathNavigator", "DNA0007", "_ = new System.Xml.XmlDocument().CreateNavigator()!.Select(input);"),
        new("System.Xml.XPath.XPathExpression", "DNA0007", "_ = System.Xml.XPath.XPathExpression.Compile(input);"),
        new("System.Xml.XPath.Extensions", "DNA0007", "_ = System.Xml.XPath.Extensions.XPathSelectElement(new System.Xml.Linq.XDocument(), input);"),
        new("System.Xml.Schema.XmlSchemaXPath", "DNA0007", "_ = new System.Xml.Schema.XmlSchemaXPath { XPath = input };"),
        new("System.Data.IDbCommand", "DNA0001", "((System.Data.IDbCommand)null!).CommandText = input;"),
        new("Dapper.CommandDefinition", "DNA0001", "_ = new Dapper.CommandDefinition(input);"),
        new("Dapper.SqlMapper", "DNA0001", "_ = Dapper.SqlMapper.Query(null!, input);"),
        new("Npgsql.NpgsqlCommand", "DNA0001", "_ = new Npgsql.NpgsqlCommand(input);"),
        new("Microsoft.Data.SqlClient.SqlCommand", "DNA0001", "_ = new Microsoft.Data.SqlClient.SqlCommand(input);"),
        new("MySqlConnector.MySqlCommand", "DNA0001", "_ = new MySqlConnector.MySqlCommand(input);"),
        new("Npgsql.NpgsqlBatchCommand", "DNA0001", "_ = new Npgsql.NpgsqlBatchCommand(input);"),
        new("Npgsql.NpgsqlDataSource", "DNA0001", "_ = Npgsql.NpgsqlDataSource.Create(\"Host=localhost\").CreateCommand(input);"),
        new("MySql.Data.MySqlClient.MySqlHelper", "DNA0001", "_ = MySql.Data.MySqlClient.MySqlHelper.ExecuteNonQuery(\"connection\", input);"),
        new("System.Data.SQLite.SQLiteCommand", "DNA0001", "_ = System.Data.SQLite.SQLiteCommand.Execute(input, System.Data.SQLite.SQLiteExecuteType.NonQuery, \"Data Source=:memory:;\");"),
        new("Microsoft.EntityFrameworkCore.RelationalDatabaseFacadeExtensions", "DNA0001", "_ = Microsoft.EntityFrameworkCore.RelationalDatabaseFacadeExtensions.ExecuteSqlRaw(null!, input);"),
        new("Microsoft.EntityFrameworkCore.RelationalQueryableExtensions", "DNA0001", "_ = Microsoft.EntityFrameworkCore.RelationalQueryableExtensions.FromSqlRaw(null!, input);"),
        new("System.Net.Http.HttpClient", "DNA0011", "_ = new System.Net.Http.HttpClient().GetStringAsync(input);"),
        new("Grpc.Net.Client.GrpcChannel", "DNA0011", "_ = Grpc.Net.Client.GrpcChannel.ForAddress(input);"),
        new("System.Net.Http.HttpRequestMessage", "DNA0011", "_ = new System.Net.Http.HttpRequestMessage(System.Net.Http.HttpMethod.Get, input);"),
        new("Microsoft.CodeAnalysis.CSharp.Scripting.CSharpScript", "DNA0012", "_ = Microsoft.CodeAnalysis.CSharp.Scripting.CSharpScript.EvaluateAsync(input);")
    ];

    [Fact]
    public void Every_built_in_sink_type_has_a_compiled_witness()
    {
        var expected = new ConfigurationReader().GetBuiltinConfiguration().Sinks
            .Select(sink => (sink.Type, Rule: RuleFor(sink.TaintTypes.Single())))
            .OrderBy(item => item.Type, StringComparer.Ordinal)
            .ThenBy(item => item.Rule, StringComparer.Ordinal);
        var actual = Probes.Select(probe => (probe.Type, probe.Rule))
            .OrderBy(item => item.Type, StringComparer.Ordinal)
            .ThenBy(item => item.Rule, StringComparer.Ordinal);
        Assert.Equal(expected, actual);
    }

    public static IEnumerable<object[]> SinkCases => Probes.Select(probe => new object[] { probe.Type, probe.Rule });

    [Theory]
    [InlineData("_ = new Microsoft.Data.SqlClient.SqlCommand { CommandText = input };")]
    [InlineData("_ = new MySqlConnector.MySqlCommand { CommandText = input };")]
    public async Task Real_sql_provider_command_text_uses_the_interface_sink(string statement)
    {
        var tree = CSharpSyntaxTree.ParseText(SourceFor(statement),
            new CSharpParseOptions(LanguageVersion.Preview), "SqlProviderProbe.cs");
        var compilation = CSharpCompilation.Create("SqlProviderProbe", [tree], References,
            new CSharpCompilationOptions(OutputKind.DynamicallyLinkedLibrary));
        Assert.Empty(compilation.GetDiagnostics().Where(diagnostic => diagnostic.Severity == DiagnosticSeverity.Error));
        var diagnostics = await compilation.WithAnalyzers([new SqlInjectionTaintAnalyzer()])
            .GetAnalyzerDiagnosticsAsync();
        Assert.Contains(diagnostics, diagnostic => diagnostic.Id == "DNA0001");
    }

    [Theory]
    [MemberData(nameof(SinkCases))]
    public async Task Built_in_sink_is_reached_by_its_rule(string type, string rule)
    {
        var probe = Assert.Single(Probes.Where(item => item.Type == type && item.Rule == rule));
        var source = SourceFor(probe.Statement);
        var tree = CSharpSyntaxTree.ParseText(source, new CSharpParseOptions(LanguageVersion.Preview), "SinkProbe.cs");
        var compilation = CSharpCompilation.Create("SinkProbe", [tree], References,
            new CSharpCompilationOptions(OutputKind.DynamicallyLinkedLibrary));
        var errors = compilation.GetDiagnostics().Where(diagnostic => diagnostic.Severity == DiagnosticSeverity.Error);
        Assert.Empty(errors);
        var analyzer = AnalyzerFor(rule);
        var diagnostics = await compilation.WithAnalyzers([analyzer]).GetAnalyzerDiagnosticsAsync();
        Assert.Contains(diagnostics, diagnostic => diagnostic.Id == rule);
    }

    private static string SourceFor(string statement) => StubTypes + "\n" + """
            [Microsoft.AspNetCore.Mvc.ApiController]
            public class Probe : Microsoft.AspNetCore.Mvc.ControllerBase
            {
                public void Run(string input)
                {
                    // SINK
            """ + "\n" + statement + "\n" + """
                }
            }
            public class TestPage : Microsoft.AspNetCore.Mvc.RazorPages.PageModel
            {
                public object DoRedirect(string url) => Redirect(url);
                public object DoRedirectPermanent(string url) => RedirectPermanent(url);
                public object DoRedirectPreserveMethod(string url) => RedirectPreserveMethod(url);
                public object DoRedirectPermanentPreserveMethod(string url) => RedirectPermanentPreserveMethod(url);
            }
            """;

    private static readonly MetadataReference[] References =
        ((string)AppContext.GetData("TRUSTED_PLATFORM_ASSEMBLIES")!).Split(Path.PathSeparator)
        .Select(path => MetadataReference.CreateFromFile(path))
        .Concat(new[]
        {
            MetadataReference.CreateFromFile(typeof(Org.BouncyCastle.Crypto.Parameters.KeyParameter).Assembly.Location),
            MetadataReference.CreateFromFile(typeof(NSec.Cryptography.AeadAlgorithm).Assembly.Location),
            MetadataReference.CreateFromFile(typeof(Sodium.SecretBox).Assembly.Location),
            MetadataReference.CreateFromFile(typeof(Microsoft.Data.SqlClient.SqlCommand).Assembly.Location),
            MetadataReference.CreateFromFile(typeof(MySqlConnector.MySqlCommand).Assembly.Location),
            MetadataReference.CreateFromFile(typeof(Grpc.Net.Client.GrpcChannel).Assembly.Location)
        }).ToArray();

    private static DiagnosticAnalyzer AnalyzerFor(string rule) => rule switch
    {
        "DNA0001" => new SqlInjectionTaintAnalyzer(),
        "DNA0002" => new CommandInjectionTaintAnalyzer(),
        "DNA0003" => new XssTaintAnalyzer(),
        "DNA0004" => new PathTraversalTaintAnalyzer(),
        "DNA0005" => new OpenRedirectTaintAnalyzer(),
        "DNA0006" => new LdapFilterTaintAnalyzer(),
        "DNA0007" => new XPathTaintAnalyzer(),
        "DNA0009" => new HardcodedPasswordAnalyzer(),
        "DNA0011" => new ServerSideRequestForgeryTaintAnalyzer(),
        "DNA0012" => new DynamicCodeExecutionTaintAnalyzer(),
        "DNA0021" => new XmlExternalEntityTaintAnalyzer(),
        _ => throw new ArgumentOutOfRangeException(nameof(rule))
    };

    private static string RuleFor(TaintType type) => type switch
    {
        TaintType.SqlInjection => "DNA0001",
        TaintType.CommandInjection => "DNA0002",
        TaintType.CrossSiteScripting => "DNA0003",
        TaintType.PathEscape => "DNA0004",
        TaintType.OpenRedirect => "DNA0005",
        TaintType.LdapDnInjection or TaintType.LdapFilterInjection => "DNA0006",
        TaintType.XPathInjection => "DNA0007",
        TaintType.HardcodedSecret => "DNA0009",
        TaintType.ServerSideRequestForgery => "DNA0011",
        TaintType.DynamicCodeExecution => "DNA0012",
        TaintType.XmlExternalEntity => "DNA0021",
        _ => throw new ArgumentOutOfRangeException(nameof(type))
    };

    private const string StubTypes = """
        namespace System.DirectoryServices
        {
            public sealed class DirectorySearcher
            {
                public DirectorySearcher(string filter) { }
                public string Filter { get; set; } = "";
            }
            public sealed class DirectoryEntry
            {
                public DirectoryEntry(string path) { }
                public string Path { get; set; } = "";
            }
        }
        namespace MySql.Data.MySqlClient
        {
            public static class MySqlHelper
            {
                public static int ExecuteDataRow(string connectionString, string commandText) => 0;
                public static int ExecuteDataRowAsync(string connectionString, string commandText) => 0;
                public static int ExecuteDataset(string connectionString, string commandText) => 0;
                public static int ExecuteDatasetAsync(string connectionString, string commandText) => 0;
                public static int ExecuteNonQuery(string connectionString, string commandText) => 0;
                public static int ExecuteNonQueryAsync(string connectionString, string commandText) => 0;
                public static int ExecuteReader(string connectionString, string commandText) => 0;
                public static int ExecuteReaderAsync(string connectionString, string commandText) => 0;
                public static int ExecuteScalar(string connectionString, string commandText) => 0;
                public static int ExecuteScalarAsync(string connectionString, string commandText) => 0;
                public static void UpdateDataSet(string connectionString, string commandText, System.Data.DataSet dataSet, string tableName) { }
                public static System.Threading.Tasks.Task UpdateDataSetAsync(string connectionString, string commandText, System.Data.DataSet dataSet, string tableName) => System.Threading.Tasks.Task.CompletedTask;
            }
        }
        namespace System.Data.SQLite
        {
            public enum SQLiteExecuteType { NonQuery }
            public sealed class SQLiteCommand
            {
                public static int Execute(string commandText, SQLiteExecuteType executeType, string connectionString) => 0;
            }
        }
        namespace Dapper
        {
            public readonly struct CommandDefinition
            {
                public CommandDefinition(string commandText) { }
            }
            public static class SqlMapper
            {
                public static object Execute(object cnn, string sql) => new object();
                public static object ExecuteAsync(object cnn, string sql) => new object();
                public static object ExecuteReader(object cnn, string sql) => new object();
                public static object ExecuteReaderAsync(object cnn, string sql) => new object();
                public static object ExecuteScalar(object cnn, string sql) => new object();
                public static object ExecuteScalarAsync(object cnn, string sql) => new object();
                public static object Query(object cnn, string sql) => new object();
                public static object QueryAsync(object cnn, string sql) => new object();
                public static object QueryFirst(object cnn, string sql) => new object();
                public static object QueryFirstAsync(object cnn, string sql) => new object();
                public static object QueryFirstOrDefault(object cnn, string sql) => new object();
                public static object QueryFirstOrDefaultAsync(object cnn, string sql) => new object();
                public static object QueryMultiple(object cnn, string sql) => new object();
                public static object QueryMultipleAsync(object cnn, string sql) => new object();
                public static object QuerySingle(object cnn, string sql) => new object();
                public static object QuerySingleAsync(object cnn, string sql) => new object();
                public static object QuerySingleOrDefault(object cnn, string sql) => new object();
                public static object QuerySingleOrDefaultAsync(object cnn, string sql) => new object();
                public static object QueryUnbufferedAsync(object cnn, string sql) => new object();
            }
        }
        namespace Npgsql
        {
            public sealed class NpgsqlCommand
            {
                public NpgsqlCommand(string cmdText) { }
            }
            public sealed class NpgsqlBatchCommand
            {
                public NpgsqlBatchCommand(string commandText) { }
                public string CommandText { get; set; } = "";
            }
            public sealed class NpgsqlDataSource
            {
                public static NpgsqlDataSource Create(string connectionString) => new NpgsqlDataSource();
                public object CreateCommand(string commandText) => new object();
            }
        }
        namespace Microsoft.EntityFrameworkCore
        {
            public static class RelationalDatabaseFacadeExtensions
            {
                public static int SqlQueryRaw(object databaseFacade, string sql) => 0;
                public static int ExecuteSqlRaw(object databaseFacade, string sql) => 0;
                public static int ExecuteSqlRawAsync(object databaseFacade, string sql) => 0;
            }
            public static class RelationalQueryableExtensions
            {
                public static object FromSqlRaw(object source, string sql) => new object();
            }
        }
        namespace Microsoft.CodeAnalysis.CSharp.Scripting
        {
            public static class CSharpScript
            {
                public static object EvaluateAsync(string code) => new object();
                public static object RunAsync(string code) => new object();
            }
        }
        """;
}
