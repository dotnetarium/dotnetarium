# Releasing 2.x

The `release/1.x` branch and 1.x tags remain available for VB.NET and .NET
Framework 4.8 projects. New features go to 2.x, whose source of truth is
`main`. Both 2.x packages use the same version.

## One-time NuGet setup

1. In GitHub repository settings, create the `nuget-publish` environment.
   Restrict deployments to `v2.*` tags. Add yourself as a required reviewer and
   enable **Prevent self-review**. Leave **Allow administrators to bypass
   configured protection rules** enabled. If a release was initiated under your
   GitHub account, use **Start all waiting jobs** to bypass the pending
   publishing job as an administrator yourself; agents must not bypass protection
   rules. If another account initiated it, you
   can use the normal **Review deployments** approval instead.
2. In the `dbalikhin` NuGet.org account, add a Trusted Publishing policy with:
   GitHub owner `dotnetarium`, repository `dotnetarium`, workflow file
   `publish.yml` (filename only), and environment `nuget-publish`. Enter that
   environment value so the policy matches the publishing job.
3. Allow publishing new packages and new versions for `Dotnetarium*`. The
   pattern covers `Dotnetarium.Analyzers` and `dotnetarium`. No NuGet API key
   secret is needed.

## Release

1. Set the same version in `Dotnetarium.Analyzers/Dotnetarium.Analyzers.csproj`
   and `Dotnetarium.Tool/Dotnetarium.Tool.csproj`. Align assembly, file and
   informational versions in `Directory.Build.props`. Check existing GitHub
   releases and both NuGet package version histories before selecting the next
   version; an already-published version cannot be reused. Merge the change to `main`
   after CI passes.
2. Tag that merged commit `v<version>`, such as `v2.0.0`. Verify the tag
   points to the release commit before publishing the GitHub release.
3. Publish a GitHub release for that tag. Keep the description to short
   **Features** and **Bug fixes** bullets, any essential upgrade note, and a
   full changelog link.
4. The release workflow checks the tag, tests and packs both packages, then
   waits at the `nuget-publish` environment. Approve it or use the administrator
   bypass as described above. The publishing job obtains a short-lived NuGet
   credential, publishes both packages, and adds
   the `.nupkg` files to the GitHub release. Verify both package pages and a
   fresh `dotnet tool install --global dotnetarium` after indexing.
