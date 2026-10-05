using System.Runtime.CompilerServices;
using Analyzer.Utilities;
using Analyzer.Utilities.Extensions;
using Analyzer.Utilities.FlowAnalysis.Analysis.TaintedDataAnalysis;
using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.CSharp;

namespace Dotnetarium.Analyzers.Tests;

public sealed class MetadataHelperCacheTests
{
    [Fact]
    public void Active_compilation_retains_helpers_across_collection()
    {
        var compilation = Compile();
        var provider = WellKnownTypeProvider.GetOrCreate(compilation);
        Assert.True(DisposeAnalysisHelper.TryGetOrCreate(compilation, out var helper));
        var predicate = DisposeAnalysisHelper.GetIsDisposableDelegate(compilation);
        var method = (IMethodSymbol)compilation.GetTypeByMetadataName("Work")!.GetMembers("Run").Single();
        var block = method.GetTopmostOperationBlock(compilation)!;
        var graph = block.GetEnclosingControlFlowGraph();
        var registrations = DependencyInjectionRegistrationModel.GetOrCreate(compilation);

        Collect();

        Assert.Same(provider, WellKnownTypeProvider.GetOrCreate(compilation));
        Assert.True(DisposeAnalysisHelper.TryGetOrCreate(compilation, out var repeated));
        Assert.Same(helper, repeated);
        Assert.Same(predicate, DisposeAnalysisHelper.GetIsDisposableDelegate(compilation));
        Assert.Same(block, method.GetTopmostOperationBlock(compilation));
        Assert.Same(graph, block.GetEnclosingControlFlowGraph());
        Assert.Same(registrations, DependencyInjectionRegistrationModel.GetOrCreate(compilation));
        Assert.True(predicate(compilation.GetTypeByMetadataName("Sync")));
        Assert.True(predicate(compilation.GetTypeByMetadataName("Async")));
        Assert.True(predicate(compilation.GetTypeByMetadataName("Pattern")));
        Assert.True(predicate(compilation.GetTypeByMetadataName("System.Runtime.CompilerServices.ConfiguredAsyncDisposable")));
        Assert.False(predicate(compilation.GetTypeByMetadataName("Plain")));
        Assert.False(predicate(null));
    }

    [Fact]
    public async Task Concurrent_compilations_keep_independent_metadata_symbols()
    {
        var compilations = Enumerable.Range(0, 8).Select(_ => Compile()).ToArray();
        var providers = await Task.WhenAll(compilations.Select(compilation => Task.Run(() =>
        {
            var provider = WellKnownTypeProvider.GetOrCreate(compilation);
            Parallel.For(0, 16, _ =>
            {
                Assert.Same(provider, WellKnownTypeProvider.GetOrCreate(compilation));
                Assert.True(DisposeAnalysisHelper.GetIsDisposableDelegate(compilation)(compilation.GetTypeByMetadataName("Sync")));
            });
            return provider;
        })));
        for (var index = 0; index < compilations.Length; index++)
        {
            Assert.Same(compilations[index], providers[index].Compilation);
            Assert.DoesNotContain(providers.Take(index), provider => ReferenceEquals(provider, providers[index]));
        }
    }

    [Fact]
    public void Completed_compilation_and_its_helper_cycle_are_collectible()
    {
        var references = CreateUnreferencedHelpers();
        Collect();
        Assert.All(references, reference => Assert.False(reference.IsAlive));
    }

    [MethodImpl(MethodImplOptions.NoInlining)]
    private static WeakReference[] CreateUnreferencedHelpers()
    {
        var compilation = Compile();
        var provider = WellKnownTypeProvider.GetOrCreate(compilation);
        Assert.True(DisposeAnalysisHelper.TryGetOrCreate(compilation, out var helper));
        var method = (IMethodSymbol)compilation.GetTypeByMetadataName("Work")!.GetMembers("Run").Single();
        var block = method.GetTopmostOperationBlock(compilation)!;
        var graph = block.GetEnclosingControlFlowGraph();
        var registrations = DependencyInjectionRegistrationModel.GetOrCreate(compilation);
        return [new(compilation), new(provider), new(helper!), new(block), new(graph!), new(registrations)];
    }

    private static void Collect()
    {
        GC.Collect();
        GC.WaitForPendingFinalizers();
        GC.Collect();
    }

    private static CSharpCompilation Compile() => CSharpCompilation.Create("MetadataCache",
        [CSharpSyntaxTree.ParseText("""
            using System;
            using System.Threading.Tasks;
            class Sync : IDisposable { public void Dispose() {} }
            class Async : IAsyncDisposable { public ValueTask DisposeAsync() => default; }
            ref struct Pattern { public void Dispose() {} }
            class Plain { public void Dispose() {} }
            class Work { public static object Run(object value) { return value; } }
            """)], [MetadataReference.CreateFromFile(typeof(object).Assembly.Location)],
        new CSharpCompilationOptions(OutputKind.DynamicallyLinkedLibrary));
}
