using Dotnetarium.Analyzers.Taint;

namespace Dotnetarium.Analyzers.Tests;

public sealed class JavaScriptExecutionTests
{
    [Theory]
    [InlineData("eval", "input", 1)]
    [InlineData("window.eval", "input", 1)]
    [InlineData("globalThis.eval", "input", 1)]
    [InlineData("console.log", "input", 0)]
    [InlineData("setText", "input", 0)]
    [InlineData("eval", "\"fixed\"", 0)]
    public async Task Only_known_global_eval_dispatch_is_an_execution_sink(string function, string value, int expected)
    {
        var source = """
            using Microsoft.AspNetCore.Mvc;
            using Microsoft.JSInterop;
            public class Demo : ControllerBase {
                public async System.Threading.Tasks.Task Run(string input, [FromServices] IJSRuntime js) {
            """ + $"await js.InvokeVoidAsync(\"{function}\", {value});" + """
                }
            }
            """;
        var diagnostics = await FrameworkProbe.Analyze(source, new XssTaintAnalyzer());
        Assert.Equal(expected, diagnostics.Count(d => d.Id == "DNA0003"));
    }
}
