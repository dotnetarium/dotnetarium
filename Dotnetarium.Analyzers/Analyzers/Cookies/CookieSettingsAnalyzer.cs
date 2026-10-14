using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Linq;
using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.Diagnostics;
using Microsoft.CodeAnalysis.Operations;

namespace Dotnetarium.Analyzers.Cookies
{
    [DiagnosticAnalyzer(LanguageNames.CSharp)]
    public sealed class CookieSettingsAnalyzer : DiagnosticAnalyzer
    {
        public override ImmutableArray<DiagnosticDescriptor> SupportedDiagnostics =>
            ImmutableArray.Create(DnaRuleCatalog.CookieConfiguration);

        public override void Initialize(AnalysisContext context)
        {
            context.EnableConcurrentExecution();
            context.ConfigureGeneratedCodeAnalysis(GeneratedCodeAnalysisFlags.Analyze | GeneratedCodeAnalysisFlags.ReportDiagnostics);
            context.RegisterOperationBlockAction(AnalyzeBlock);
        }

        private static void AnalyzeBlock(OperationBlockAnalysisContext context)
        {
            var cookies = new Dictionary<string, CookieFinding>(StringComparer.Ordinal);
            foreach (var root in context.OperationBlocks)
            {
                foreach (var operation in root.DescendantsAndSelf())
                {
                    if (context.IsGeneratedCode && !RazorCodeAnalysis.IsUserCode(operation.Syntax)) continue;
                    if (operation is ISimpleAssignmentOperation assignment &&
                        assignment.Target is IPropertyReferenceOperation property &&
                        TryGetSensitiveCookie(property, out var key, out var name))
                    {
                        AddSetting(cookies, key, name, assignment.Syntax.GetLocation(), property.Property.Name, assignment.Value);
                    }
                    else if (operation is IInvocationOperation invocation)
                    {
                        AnalyzeAppend(invocation, cookies);
                    }
                }
            }

            foreach (var finding in cookies.Values)
            {
                if (finding.SameSiteNone && !finding.SecureAlways)
                    finding.Reasons.Add("SameSite=None requires SecurePolicy=Always");
                if (finding.Reasons.Count == 0) continue;
                context.ReportDiagnostic(Diagnostic.Create(
                    DnaRuleCatalog.CookieConfiguration,
                    finding.Location,
                    finding.Name,
                    string.Join(", ", finding.Reasons.OrderBy(reason => reason, StringComparer.Ordinal))));
            }
        }

        private static bool TryGetSensitiveCookie(IPropertyReferenceOperation property, out string key, out string name)
        {
            if (property.Instance is IPropertyReferenceOperation cookieProperty &&
                cookieProperty.Property.Name == "Cookie" &&
                GetSensitiveCookieName(cookieProperty.Property.ContainingType) is string directName)
            {
                IAnonymousFunctionOperation? owner = null;
                for (IOperation? ancestor = cookieProperty.Parent; ancestor != null; ancestor = ancestor.Parent)
                {
                    if (ancestor is IAnonymousFunctionOperation function)
                    {
                        owner = function;
                        break;
                    }
                }
                key = cookieProperty.Property.ContainingType.ToDisplayString() + ":" +
                      (owner?.Syntax.SpanStart ?? 0).ToString(System.Globalization.CultureInfo.InvariantCulture) + ":" +
                      cookieProperty.Syntax;
                name = directName;
                return true;
            }

            for (IOperation? ancestor = property.Parent; ancestor != null; ancestor = ancestor.Parent)
            {
                if (ancestor is IObjectCreationOperation creation &&
                    creation.Type?.ToDisplayString() == "Microsoft.AspNetCore.Http.CookieBuilder" &&
                    creation.Parent is ISimpleAssignmentOperation cookieAssignment &&
                    cookieAssignment.Target is IPropertyReferenceOperation target &&
                    target.Property.Name == "Cookie" &&
                    GetSensitiveCookieName(target.Property.ContainingType) is string initializerName)
                {
                    key = creation.Syntax.SpanStart.ToString(System.Globalization.CultureInfo.InvariantCulture);
                    name = initializerName;
                    return true;
                }
            }

            key = string.Empty;
            name = string.Empty;
            return false;
        }

        private static string? GetSensitiveCookieName(INamedTypeSymbol type) => type.ToDisplayString() switch
        {
            "Microsoft.AspNetCore.Authentication.Cookies.CookieAuthenticationOptions" => "authentication",
            "Microsoft.AspNetCore.Builder.SessionOptions" => "session",
            _ => null
        };

        private static void AddSetting(Dictionary<string, CookieFinding> cookies, string key, string name,
            Location location, string property, IOperation value)
        {
            string? reason = property switch
            {
                "HttpOnly" when value.ConstantValue.HasValue && value.ConstantValue.Value is false => "HttpOnly=false",
                "SecurePolicy" when IsEnumMember(value, "Microsoft.AspNetCore.Http.CookieSecurePolicy", "None") => "SecurePolicy=None",
                _ => null
            };
            bool sameSiteNone = property == "SameSite" &&
                IsEnumMember(value, "Microsoft.AspNetCore.Http.SameSiteMode", "None");
            bool secureAlways = property == "SecurePolicy" &&
                IsEnumMember(value, "Microsoft.AspNetCore.Http.CookieSecurePolicy", "Always");
            if (reason == null && !sameSiteNone && !secureAlways) return;
            if (!cookies.TryGetValue(key, out var finding))
                cookies.Add(key, finding = new CookieFinding(name, location));
            if (reason != null) finding.Reasons.Add(reason);
            if (sameSiteNone) finding.SameSiteNone = true;
            if (secureAlways) finding.SecureAlways = true;
        }

        private static void AnalyzeAppend(IInvocationOperation invocation, Dictionary<string, CookieFinding> cookies)
        {
            if (invocation.TargetMethod.Name != "Append" ||
                invocation.TargetMethod.ContainingType.ToDisplayString() != "Microsoft.AspNetCore.Http.IResponseCookies" ||
                invocation.Arguments.Length < 3)
                return;

            IOperation value = invocation.Arguments[2].Value;
            while (value is IConversionOperation conversion) value = conversion.Operand;
            if (value is not IObjectCreationOperation creation ||
                creation.Type?.ToDisplayString() != "Microsoft.AspNetCore.Http.CookieOptions")
                return;

            bool sameSiteNone = false;
            bool secure = false;
            foreach (var initializer in creation.Initializer?.Initializers ?? ImmutableArray<IOperation>.Empty)
            {
                if (initializer is not ISimpleAssignmentOperation assignment ||
                    assignment.Target is not IPropertyReferenceOperation property)
                    continue;
                if (property.Property.Name == "SameSite")
                    sameSiteNone = IsEnumMember(assignment.Value, "Microsoft.AspNetCore.Http.SameSiteMode", "None");
                if (property.Property.Name == "Secure" && assignment.Value.ConstantValue.HasValue)
                    secure = assignment.Value.ConstantValue.Value is true;
            }

            // SameSite=None without Secure is rejected by modern browsers. Other
            // custom cookies need a sensitivity model before flagging defaults.
            if (!sameSiteNone || secure) return;
            var cookieName = invocation.Arguments[0].Value.ConstantValue.Value as string ?? "custom";
            var key = invocation.Syntax.SpanStart.ToString(System.Globalization.CultureInfo.InvariantCulture);
            var finding = new CookieFinding(cookieName, invocation.Syntax.GetLocation());
            finding.Reasons.Add("SameSite=None requires Secure=true");
            cookies[key] = finding;
        }

        private static bool IsEnumMember(IOperation value, string enumType, string member)
        {
            while (value is IConversionOperation conversion) value = conversion.Operand;
            return value is IFieldReferenceOperation field &&
                   field.Field.Name == member &&
                   field.Field.ContainingType.ToDisplayString() == enumType;
        }

        private sealed class CookieFinding
        {
            internal CookieFinding(string name, Location location)
            {
                Name = name;
                Location = location;
            }

            internal string Name { get; }
            internal Location Location { get; }
            internal bool SameSiteNone { get; set; }
            internal bool SecureAlways { get; set; }
            internal HashSet<string> Reasons { get; } = new HashSet<string>(StringComparer.Ordinal);
        }
    }
}
