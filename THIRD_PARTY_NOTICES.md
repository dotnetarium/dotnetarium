# Third-party notices

The `Roslyn` directory contains Microsoft analyzer utility and flow analysis
source, with Dotnetarium changes to taint and interprocedural analysis. Source
files retain their Microsoft copyright and license headers. Files marked MIT
are covered by [`Roslyn/License.txt`](Roslyn/License.txt); files marked Apache
License 2.0 are covered by [`LICENSE`](LICENSE). These notices also apply when
the sources are compiled into the Dotnetarium analyzer and tool packages.

The `Dotnetarium.Analyzers` analyzer, its configuration and rules, and the
`Dotnetarium.Tool` CLI are released under Apache License 2.0. Third-party
NuGet dependencies retain their own licenses.

## GitHub CodeQL Action fingerprints

`Dotnetarium.Tool/SarifFingerprints.cs` adapts the line-fingerprint algorithm
from [`github/codeql-action/src/fingerprints.ts`](https://github.com/github/codeql-action/blob/24c54180a607b1449ed407dd24f251e4e9147c8d/src/fingerprints.ts).
The corresponding tests include upstream compatibility vectors. These portions
are covered by the following license:

MIT License

Copyright (c) 2020 GitHub

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
