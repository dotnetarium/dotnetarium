using Dotnetarium.Analyzers.Taint;

namespace Dotnetarium.Analyzers.Tests;

public sealed class XmlExternalEntityTests
{
    [Theory]
    [InlineData("XmlReader.Create(new StringReader(input), new XmlReaderSettings { DtdProcessing = DtdProcessing.Parse, XmlResolver = new XmlUrlResolver() });", 1)]
    [InlineData("XmlReader.Create(new MemoryStream(Encoding.UTF8.GetBytes(input)), new XmlReaderSettings { DtdProcessing = DtdProcessing.Parse, XmlResolver = new XmlUrlResolver() });", 1)]
    [InlineData("XmlReader.Create(new StringReader(input));", 0)]
    [InlineData("XmlReader.Create(new StringReader(input), new XmlReaderSettings { DtdProcessing = DtdProcessing.Parse });", 0)]
    [InlineData("XmlReader.Create(new StringReader(input), new XmlReaderSettings { DtdProcessing = DtdProcessing.Prohibit, XmlResolver = new XmlUrlResolver() });", 0)]
    [InlineData("XmlReader.Create(new StringReader(input), new XmlReaderSettings { DtdProcessing = DtdProcessing.Parse, XmlResolver = null });", 0)]
    [InlineData("XmlReader.Create(new StringReader(input), new XmlReaderSettings { DtdProcessing = DtdProcessing.Parse, XmlResolver = new XmlPreloadedResolver() });", 0)]
    [InlineData("XmlReader.Create(input, new XmlReaderSettings { DtdProcessing = DtdProcessing.Parse, XmlResolver = new XmlUrlResolver() });", 0)]
    [InlineData("XmlReader.Create(new StringReader(\"<fixed/>\"), new XmlReaderSettings { DtdProcessing = DtdProcessing.Parse, XmlResolver = new XmlUrlResolver() });", 0)]
    [InlineData("var settings = new XmlReaderSettings(); settings.DtdProcessing = DtdProcessing.Parse; settings.XmlResolver = new XmlUrlResolver(); XmlReader.Create(new StringReader(input), settings);", 1)]
    [InlineData("var settings = new XmlReaderSettings { DtdProcessing = DtdProcessing.Parse, XmlResolver = new XmlUrlResolver() }; var alias = settings; alias.XmlResolver = null; XmlReader.Create(new StringReader(input), settings);", 0)]
    [InlineData("var settings = new XmlReaderSettings { DtdProcessing = DtdProcessing.Parse, XmlResolver = new XmlUrlResolver() }; if (enabled) settings.XmlResolver = null; XmlReader.Create(new StringReader(input), settings);", 0)]
    [InlineData("var settings = new XmlReaderSettings { DtdProcessing = DtdProcessing.Parse }; if (enabled) settings.XmlResolver = new XmlUrlResolver(); else settings.XmlResolver = new XmlUrlResolver(); XmlReader.Create(new StringReader(input), settings);", 1)]
    [InlineData("var settings = new XmlReaderSettings { DtdProcessing = DtdProcessing.Parse, XmlResolver = new XmlUrlResolver() }; settings = new XmlReaderSettings(); XmlReader.Create(new StringReader(input), settings);", 0)]
    [InlineData("new XmlDocument { XmlResolver = new XmlUrlResolver() }.LoadXml(input);", 1)]
    [InlineData("new XmlDocument().LoadXml(input);", 0)]
    [InlineData("new XmlDocument { XmlResolver = null }.LoadXml(input);", 0)]
    [InlineData("var document = new XmlDocument { XmlResolver = new XmlUrlResolver() }; document.XmlResolver = null; document.LoadXml(input);", 0)]
    [InlineData("var reader = new XmlTextReader(new StringReader(input)) { DtdProcessing = DtdProcessing.Parse, XmlResolver = new XmlUrlResolver() }; reader.Read();", 1)]
    [InlineData("var reader = new XmlTextReader(new StringReader(input)) { DtdProcessing = DtdProcessing.Parse, XmlResolver = null }; reader.Read();", 0)]
    public async Task Untrusted_XML_requires_explicit_unrestricted_external_resolution(string body, int expected)
    {
        var findings = await FrameworkProbe.Analyze("""
            using System;
            using System.IO;
            using System.Text;
            using System.Xml;
            using System.Xml.Resolvers;
            public static class Demo { public static void Run(bool enabled) { var input = Console.ReadLine();
            """ + body + "}}", new XmlExternalEntityTaintAnalyzer(), includeLocalSources: true);
        Assert.True(expected == findings.Length, $"{body}: expected {expected}, actual {findings.Length}");
        Assert.All(findings, finding => Assert.NotEmpty(finding.AdditionalLocations));
    }
}
