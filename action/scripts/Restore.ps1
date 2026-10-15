$ErrorActionPreference = 'Stop'
$restoreArguments = @('restore', $env:DNA_TARGET, "-p:Configuration=$env:DNA_CONFIGURATION", '--nologo')
# Keep the complete project-reference restore graph; framework selects the scan,
# rather than overriding TargetFramework on every referenced project.
& dotnet @restoreArguments
if ($LASTEXITCODE -ne 0) { throw 'Dependency restore failed. Fix feed/SDK setup or use restore: false with prepared assets.' }
