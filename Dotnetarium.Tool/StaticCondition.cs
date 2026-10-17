namespace Dotnetarium.Tool;

// A bounded, data-only subset of MSBuild conditions. Never invokes MSBuild,
// arbitrary property functions, tasks or targets. Unknown syntax invalidates the whole expression,
// including branches whose Boolean value would otherwise short-circuit.
internal static class StaticCondition
{
    // Recognize this conventional TFM check as data, not via reflection or an
    // MSBuild evaluator. Other methods, overloads and nested expressions remain unknown.
    internal static bool TryExpandFunctions(string expression, IReadOnlyDictionary<string, string> properties, out string expanded)
    {
        expanded = expression;
        if (expression.Length > 65536) return false;
        var output = new System.Text.StringBuilder();
        var position = 0;
        while (expression.IndexOf("$(", position, StringComparison.Ordinal) is var start && start >= 0)
        {
            output.Append(expression, position, start - position);
            var cursor = start + 2;
            var nameStart = cursor;
            while (cursor < expression.Length && (char.IsLetterOrDigit(expression[cursor]) || expression[cursor] == '_')) cursor++;
            var name = expression[nameStart..cursor];
            const string method = ".Contains(";
            if (name.Length == 0 || !expression.AsSpan(cursor).StartsWith(method, StringComparison.Ordinal) ||
                !properties.TryGetValue(name, out var value) || value.Contains("$(", StringComparison.Ordinal) || value.Contains('%')) return false;
            cursor += method.Length;
            while (cursor < expression.Length && char.IsWhiteSpace(expression[cursor])) cursor++;
            if (cursor == expression.Length || expression[cursor] is not ('\'' or '"')) return false;
            var quote = expression[cursor++];
            var end = expression.IndexOf(quote, cursor);
            if (end < 0) return false;
            var argument = expression[cursor..end];
            if (argument.Contains("$(", StringComparison.Ordinal) || argument.Contains('%')) return false;
            cursor = end + 1;
            while (cursor < expression.Length && char.IsWhiteSpace(expression[cursor])) cursor++;
            if (!expression.AsSpan(cursor).StartsWith("))", StringComparison.Ordinal)) return false;
            output.Append(value.Contains(argument, StringComparison.Ordinal) ? "true" : "false");
            position = cursor + 2;
        }
        output.Append(expression, position, expression.Length - position);
        expanded = output.ToString();
        return true;
    }

    internal static bool TryEvaluate(string expression, out bool value, string? projectDirectory = null)
    {
        value = false;
        if (expression.Length > 65536 || expression.Contains("$(", StringComparison.Ordinal)) return false;
        var parser = new Parser(expression, projectDirectory);
        if (!parser.TryOr(out var result) || !parser.AtEnd) return false;
        value = result;
        return true;
    }

    private sealed class Parser(string text, string? projectDirectory)
    {
        private int position;
        private int depth;
        internal bool AtEnd { get { WhiteSpace(); return position == text.Length; } }

        internal bool TryOr(out bool value)
        {
            if (!TryAnd(out value)) return false;
            while (TakeWord("or"))
            {
                if (!TryAnd(out var right)) return false;
                value |= right;
            }
            return true;
        }

        private bool TryAnd(out bool value)
        {
            if (!TryUnary(out value)) return false;
            while (TakeWord("and"))
            {
                if (!TryUnary(out var right)) return false;
                value &= right;
            }
            return true;
        }

        private bool TryUnary(out bool value)
        {
            value = false;
            if (++depth > 64) return false;
            try
            {
                if (Take("!"))
                {
                    if (!TryUnary(out var inner)) return false;
                    value = !inner;
                    return true;
                }
                if (Take("(")) return TryOr(out value) && Take(")");
                if (TakeWord("Exists"))
                {
                    if (projectDirectory == null || !Take("(") || !Operand(out var path) || !Take(")")) return false;
                    if (path.Length == 0) return true;
                    try
                    {
                        var fullPath = Path.GetFullPath(Path.Combine(projectDirectory,
                            path.Replace('\\', Path.DirectorySeparatorChar).Replace('/', Path.DirectorySeparatorChar)));
                        value = File.Exists(fullPath) || Directory.Exists(fullPath);
                        return true;
                    }
                    catch (Exception error) when (error is ArgumentException or NotSupportedException or IOException) { return false; }
                }
                if (!Operand(out var left)) return false;
                var equal = Take("==");
                if (equal || Take("!="))
                {
                    if (!Operand(out var right)) return false;
                    value = left.Equals(right, StringComparison.OrdinalIgnoreCase) == equal;
                    return true;
                }
                return bool.TryParse(left, out value);
            }
            finally { depth--; }
        }

        private bool Operand(out string value)
        {
            WhiteSpace(); value = "";
            if (position == text.Length) return false;
            if (text[position] is '\'' or '"')
            {
                var quote = text[position++];
                var end = text.IndexOf(quote, position);
                if (end < 0) return false;
                value = text[position..end]; position = end + 1;
                return true;
            }
            var start = position;
            while (position < text.Length && char.IsLetter(text[position])) position++;
            value = text[start..position];
            return bool.TryParse(value, out _);
        }

        private bool Take(string token)
        {
            WhiteSpace();
            if (!text.AsSpan(position).StartsWith(token, StringComparison.Ordinal)) return false;
            position += token.Length;
            return true;
        }

        private bool TakeWord(string token)
        {
            WhiteSpace();
            if (!text.AsSpan(position).StartsWith(token, StringComparison.OrdinalIgnoreCase)) return false;
            var end = position + token.Length;
            if (end < text.Length && (char.IsLetterOrDigit(text[end]) || text[end] == '_')) return false;
            position = end;
            return true;
        }

        private void WhiteSpace()
        {
            while (position < text.Length && char.IsWhiteSpace(text[position])) position++;
        }
    }
}
