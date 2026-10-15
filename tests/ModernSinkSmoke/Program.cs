using System;
using System.Collections.Immutable;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Reflection.PortableExecutable;
using System.Threading.Tasks;
using Dotnetarium.Analyzers.Taint;
using Dotnetarium.Config;
using Microsoft.AspNetCore.Mvc;
using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.CSharp;
using Microsoft.CodeAnalysis.Diagnostics;

var cases = new (string Name, string Statement, string Rule, bool ShouldWarn)[]
{
    ("directory enumeration", "System.IO.Directory.EnumerateFiles(path);", "DNA0004", false),
    ("directory enumeration of directories", "System.IO.Directory.EnumerateDirectories(path);", "DNA0004", false),
    ("directory enumeration of entries", "System.IO.Directory.EnumerateFileSystemEntries(path);", "DNA0004", false),
    ("directory listing of directories", "System.IO.Directory.GetDirectories(path);", "DNA0004", false),
    ("directory listing of entries", "System.IO.Directory.GetFileSystemEntries(path);", "DNA0004", false),
    ("directory creation", "System.IO.Directory.CreateDirectory(path);", "DNA0004", false),
    ("enumerated file delete", "foreach (var file in System.IO.Directory.EnumerateFiles(path)) System.IO.File.Delete(file);", "DNA0004", true),
    ("file object read", "new System.IO.FileInfo(path).OpenRead();", "DNA0004", true),
    ("file object construction", "_ = new System.IO.FileInfo(path);", "DNA0004", false),
    ("directory symlink target", "System.IO.Directory.CreateSymbolicLink(\"link\", path);", "DNA0004", true),
    ("file handle", "System.IO.File.OpenHandle(path);", "DNA0004", true),
    ("file symlink target", "System.IO.File.CreateSymbolicLink(\"link\", path);", "DNA0004", true),
    ("file symlink path", "System.IO.File.CreateSymbolicLink(path, \"target\");", "DNA0004", true),
    ("constant directory", "System.IO.Directory.EnumerateFiles(\"fixed\");", "DNA0004", false),
    ("constant file handle", "System.IO.File.OpenHandle(\"fixed\");", "DNA0004", false),
    ("lookalike method", "FakeFile.OpenHandle(path);", "DNA0004", false),
    ("EF Core scalar raw SQL", "context.Database.SqlQueryRaw<int>(path);", "DNA0001", true),
    ("EF Core constant raw SQL", "context.Database.SqlQueryRaw<int>(\"SELECT 1\");", "DNA0001", false),
    ("EF Core parameterized SQL", "context.Database.SqlQuery<int>($\"SELECT {path}\");", "DNA0001", false),
    ("DirectorySearcher constructor", "_ = new System.DirectoryServices.DirectorySearcher(path);", "DNA0006", true),
    ("DirectorySearcher filter", "new System.DirectoryServices.DirectorySearcher().Filter = path;", "DNA0006", true),
    ("DirectoryEntry constructor", "_ = new System.DirectoryServices.DirectoryEntry(path);", "DNA0006", true),
    ("DirectoryEntry path", "new System.DirectoryServices.DirectoryEntry().Path = path;", "DNA0006", true),
    ("SQLite static Execute", "_ = System.Data.SQLite.SQLiteCommand.Execute(path, System.Data.SQLite.SQLiteExecuteType.NonQuery, \"Data Source=:memory:;\");", "DNA0001", true),
    ("EF Core ExecuteSqlRaw", "_ = context.Database.ExecuteSqlRaw(path);", "DNA0001", true),
    ("EF Core ExecuteSqlRawAsync", "_ = context.Database.ExecuteSqlRawAsync(path);", "DNA0001", true),
    ("EF Core FromSqlRaw", "_ = context.Set<Row>().FromSqlRaw(path);", "DNA0001", true),
    ("EF Core safe FromSql", "_ = context.Set<Row>().FromSql($\"SELECT {path}\");", "DNA0001", false),
    ("CSharpScript EvaluateAsync", "_ = Microsoft.CodeAnalysis.CSharp.Scripting.CSharpScript.EvaluateAsync(path);", "DNA0012", true),
    ("CSharpScript RunAsync", "_ = Microsoft.CodeAnalysis.CSharp.Scripting.CSharpScript.RunAsync(path);", "DNA0012", true),
    ("Json.NET unsafe type names", "_ = new Newtonsoft.Json.JsonSerializerSettings { TypeNameHandling = Newtonsoft.Json.TypeNameHandling.All };", "DNA0008", true),
    ("Json.NET default type names", "_ = new Newtonsoft.Json.JsonSerializerSettings { TypeNameHandling = Newtonsoft.Json.TypeNameHandling.None };", "DNA0008", false),
    ("Npgsql command constructor", "_ = new Npgsql.NpgsqlCommand(path);", "DNA0001", true),
    ("Npgsql command text", "new Npgsql.NpgsqlCommand().CommandText = path;", "DNA0001", true),
    ("Npgsql batch constructor", "_ = new Npgsql.NpgsqlBatchCommand(path);", "DNA0001", true),
    ("Npgsql batch text", "new Npgsql.NpgsqlBatchCommand().CommandText = path;", "DNA0001", true),
    ("Npgsql data source command", "_ = Npgsql.NpgsqlDataSource.Create(\"Host=localhost\").CreateCommand(path);", "DNA0001", true),
    ("Dapper Query", "_ = Dapper.SqlMapper.Query(new Npgsql.NpgsqlConnection(), path);", "DNA0001", true),
    ("Dapper CommandDefinition", "_ = new Dapper.CommandDefinition(path);", "DNA0001", true),
    ("Dapper parameterized query", "_ = Dapper.SqlMapper.Query(new Npgsql.NpgsqlConnection(), \"SELECT @value\", new { value = path });", "DNA0001", false),
};

foreach (var method in new[] { "ExecuteDataRow", "ExecuteDataRowAsync", "ExecuteDataset", "ExecuteDatasetAsync",
             "ExecuteNonQuery", "ExecuteNonQueryAsync", "ExecuteReader", "ExecuteReaderAsync",
             "ExecuteScalar", "ExecuteScalarAsync" })
    cases = cases.Append(("MySqlHelper " + method,
        "_ = MySql.Data.MySqlClient.MySqlHelper." + method + "(\"server=localhost\", path);", "DNA0001", true)).ToArray();
foreach (var method in new[] { "UpdateDataSet", "UpdateDataSetAsync" })
    cases = cases.Append(("MySqlHelper " + method,
        (method.EndsWith("Async", StringComparison.Ordinal) ? "_ = " : "") +
        "MySql.Data.MySqlClient.MySqlHelper." + method + "(\"server=localhost\", path, new System.Data.DataSet(), \"table\");", "DNA0001", true)).ToArray();
foreach (var method in new[] { "Execute", "ExecuteAsync", "ExecuteReader", "ExecuteReaderAsync", "ExecuteScalar", "ExecuteScalarAsync", "QueryAsync", "QueryFirst", "QueryFirstAsync", "QueryFirstOrDefault", "QueryFirstOrDefaultAsync", "QueryMultiple", "QueryMultipleAsync", "QuerySingle", "QuerySingleAsync", "QuerySingleOrDefault", "QuerySingleOrDefaultAsync", "QueryUnbufferedAsync" })
    cases = cases.Append(("Dapper " + method,
        "_ = Dapper.SqlMapper." + method + "(new Npgsql.NpgsqlConnection(), path);", "DNA0001", true)).ToArray();

// Keep real-package witnesses synchronized with the optional-provider sink inventory.
var providerNames = new Dictionary<string, string>(StringComparer.Ordinal)
{
    ["DirectorySearcher constructor"] = "System.DirectoryServices.DirectorySearcher|M:.ctor",
    ["DirectorySearcher filter"] = "System.DirectoryServices.DirectorySearcher|P:Filter",
    ["DirectoryEntry constructor"] = "System.DirectoryServices.DirectoryEntry|M:.ctor",
    ["DirectoryEntry path"] = "System.DirectoryServices.DirectoryEntry|P:Path",
    ["SQLite static Execute"] = "System.Data.SQLite.SQLiteCommand|M:Execute",
    ["EF Core scalar raw SQL"] = "Microsoft.EntityFrameworkCore.RelationalDatabaseFacadeExtensions|M:SqlQueryRaw",
    ["EF Core ExecuteSqlRaw"] = "Microsoft.EntityFrameworkCore.RelationalDatabaseFacadeExtensions|M:ExecuteSqlRaw",
    ["EF Core ExecuteSqlRawAsync"] = "Microsoft.EntityFrameworkCore.RelationalDatabaseFacadeExtensions|M:ExecuteSqlRawAsync",
    ["EF Core FromSqlRaw"] = "Microsoft.EntityFrameworkCore.RelationalQueryableExtensions|M:FromSqlRaw",
    ["CSharpScript EvaluateAsync"] = "Microsoft.CodeAnalysis.CSharp.Scripting.CSharpScript|M:EvaluateAsync",
    ["CSharpScript RunAsync"] = "Microsoft.CodeAnalysis.CSharp.Scripting.CSharpScript|M:RunAsync",
    ["Npgsql command constructor"] = "Npgsql.NpgsqlCommand|M:.ctor",
    ["Npgsql batch constructor"] = "Npgsql.NpgsqlBatchCommand|M:.ctor",
    ["Npgsql batch text"] = "Npgsql.NpgsqlBatchCommand|P:CommandText",
    ["Npgsql data source command"] = "Npgsql.NpgsqlDataSource|M:CreateCommand",
    ["Dapper Query"] = "Dapper.SqlMapper|M:Query",
    ["Dapper CommandDefinition"] = "Dapper.CommandDefinition|M:.ctor"
};
var providerTypes = new HashSet<string>(providerNames.Values.Select(value => value.Split('|')[0]), StringComparer.Ordinal)
{
    "MySql.Data.MySqlClient.MySqlHelper",
    "Dapper.SqlMapper"
};
var configuredProviderMembers = new ConfigurationReader().GetBuiltinConfiguration().Sinks
    .Where(sink => providerTypes.Contains(sink.Type))
    .SelectMany(sink => (sink.Methods ?? Array.Empty<SinkMethod>()).Select(method => sink.Type + "|M:" + method.Name)
        .Concat((sink.Properties ?? new HashSet<string>()).Select(property => sink.Type + "|P:" + property)))
    .OrderBy(value => value, StringComparer.Ordinal).ToArray();
var witnessedProviderMembers = cases
    .Where(test => providerNames.ContainsKey(test.Name) || test.Name.StartsWith("MySqlHelper ", StringComparison.Ordinal) ||
        (test.Name.StartsWith("Dapper ", StringComparison.Ordinal) && test.ShouldWarn))
    .Select(test => providerNames.TryGetValue(test.Name, out var key) ? key :
        test.Name.StartsWith("MySqlHelper ", StringComparison.Ordinal)
            ? "MySql.Data.MySqlClient.MySqlHelper|M:" + test.Name["MySqlHelper ".Length..]
            : "Dapper.SqlMapper|M:" + test.Name["Dapper ".Length..])
    .OrderBy(value => value, StringComparer.Ordinal).ToArray();
if (!configuredProviderMembers.SequenceEqual(witnessedProviderMembers))
    throw new Exception("Real provider witnesses differ from configured sinks: " +
        "configured=" + string.Join(",", configuredProviderMembers) + "; witnessed=" + string.Join(",", witnessedProviderMembers));

var references = ((string)AppContext.GetData("TRUSTED_PLATFORM_ASSEMBLIES")!)
    .Split(Path.PathSeparator)
    .Concat(Directory.GetFiles(Path.GetDirectoryName(typeof(ControllerBase).Assembly.Location)!, "*.dll"))
    .Concat(Directory.GetFiles(AppContext.BaseDirectory, "*.dll"))
    .GroupBy(Path.GetFileName, StringComparer.OrdinalIgnoreCase)
    .Select(group => group.First())
    .Where(path =>
    {
        using var reader = new PEReader(File.OpenRead(path));
        return reader.HasMetadata;
    })
    .Select(path => MetadataReference.CreateFromFile(path))
    .ToArray();

var failures = new List<string>();
foreach (var test in cases)
{
    var source = $@"
using Microsoft.EntityFrameworkCore;
public class TestController : Microsoft.AspNetCore.Mvc.ControllerBase
{{
    public void Run(string path, DbContext context)
    {{
        {test.Statement}
    }}
}}
public static class FakeFile
{{
    public static void OpenHandle(string path) {{ }}
}}
public class Row {{ public int Id {{ get; set; }} }}";
    var compilation = CSharpCompilation.Create(
        "ModernSinkSmoke",
        new[] { CSharpSyntaxTree.ParseText(source) },
        references,
        new CSharpCompilationOptions(OutputKind.DynamicallyLinkedLibrary));
    var errors = compilation.GetDiagnostics().Where(d => d.Severity == DiagnosticSeverity.Error).ToArray();
    if (errors.Length != 0)
    {
        failures.Add($"{test.Name}: source did not compile: {string.Join("; ", errors.Select(d => d.ToString()))}");
        continue;
    }

    DiagnosticAnalyzer analyzer = test.Rule switch
    {
        "DNA0001" => new SqlInjectionTaintAnalyzer(),
        "DNA0004" => new PathTraversalTaintAnalyzer(),
        "DNA0006" => new LdapFilterTaintAnalyzer(),
        "DNA0008" => new UnsafeDeserializationSettingAnalyzer(),
        "DNA0012" => new DynamicCodeExecutionTaintAnalyzer(),
        _ => throw new Exception("Unmapped rule " + test.Rule)
    };
    var diagnostics = await compilation.WithAnalyzers(
        ImmutableArray.Create(analyzer)).GetAnalyzerDiagnosticsAsync();
    var warned = diagnostics.Any(d => d.Id == test.Rule);
    if (warned != test.ShouldWarn)
        failures.Add($"{test.Name}: expected warning={test.ShouldWarn}, got {string.Join("; ", diagnostics.Select(d => d.ToString()))}");
    else
        Console.WriteLine($"PASS {test.Name}");
}
if (failures.Count != 0)
    throw new Exception(string.Join(Environment.NewLine, failures));
