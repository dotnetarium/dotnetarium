# Final fast-profile budget comparison

> Historical measurements below retain their original loader and exit policy.
> Current scans default to no-build; `-p` selects project loading. Limits are
> informational and input quality is reported separately. See [scan modes](scan-modes.md).


October 14, 2026. Unchanged production code from `6aa39e3`, rebuilt at documentation
commit `f232c35`. Windows, Ryzen 7 255 / 16 logical processors, SDK 10.0.401,
Release; requested framework `net10.0`. All rules and **remote + local** sources
were enabled. Method and lambda/local-function depths were both **3**. Only the
work budget and loading mode changed; scans ran sequentially without profiling.

The initial 18-cell matrix was followed by repeats of all six 1,000-budget cells
to resolve startup/loading variation. The tables use those repeats at 1,000 and
the original runs at 2,000/2,500. These are observed single-run wall times, not
medians or guaranteed timings. Warm dependency caches were available.

## Wall time, cutoffs and findings

| Application | Budget | NB seconds | NB cutoffs | Project seconds | Project cutoffs | Findings NB / project |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| Vulnerable .NET app | 1,000 | 6.62 | 155 | 10.39 | 151 | 9 / 9 |
| Vulnerable .NET app | 2,000 | 7.22 | 86 | 9.48 | 87 | 12 / 12 |
| Vulnerable .NET app | 2,500 | 7.68 | 79 | 9.63 | 81 | 17 / 18 |
| Sarifintown | 1,000 | 4.67 | 362 | 7.23 | 362 | 0 / 0 |
| Sarifintown | 2,000 | 5.12 | 274 | 7.39 | 273 | 0 / 0 |
| Sarifintown | 2,500 | 5.27 | 259 | 7.54 | 266 | 1 / 1 |
| LANCommander | 1,000 | 40.24 | 2,500 | 72.02 | 4,653 | 12 / 12 |
| LANCommander | 2,000 | 40.31 | 1,836 | 80.59 | 3,562 | 16 / 16 |
| LANCommander | 2,500 | 41.02 | 1,698 | 76.08 | 3,325 | 16 / 16 |

Cutoffs count stopped compilation/rule/root analyses, not unique methods or
vulnerabilities. Cache ordering can change counts and bounded findings.

Across these three sequential scans, NB totals were 51.53 / 52.65 / 53.97 seconds,
3,017 / 2,196 / 2,036 cutoffs and 21 / 28 / 34 findings at 1,000 / 2,000 / 2,500.
Project totals were 89.64 / 97.46 / 93.25 seconds, 5,166 / 3,922 / 3,672 cutoffs
and 21 / 28 / 35 findings. The faster project sample at 2,500 is not proof that
raising the budget makes scans faster.

## Work versus depth cutoffs

Each cell below is **work / depth**; its sum equals the total cutoff count above.

| Application | Budget | NB work / depth | Project work / depth |
| --- | ---: | ---: | ---: |
| Vulnerable .NET app | 1,000 | 152 / 3 | 148 / 3 |
| Vulnerable .NET app | 2,000 | 82 / 4 | 82 / 5 |
| Vulnerable .NET app | 2,500 | 75 / 4 | 77 / 4 |
| Sarifintown | 1,000 | 245 / 117 | 249 / 113 |
| Sarifintown | 2,000 | 109 / 165 | 111 / 162 |
| Sarifintown | 2,500 | 85 / 174 | 90 / 176 |
| LANCommander | 1,000 | 1,791 / 709 | 3,922 / 731 |
| LANCommander | 2,000 | 725 / 1,111 | 2,473 / 1,089 |
| LANCommander | 2,500 | 533 / 1,165 | 2,209 / 1,116 |

## Coverage and interpretation

- Both modes analyzed 1, 3 and 21 production compilations respectively. Sarifintown
  excluded three test projects; LANCommander excluded six.
- Every 1,000- and 2,000-budget finding location was retained at 2,500 within its
  loading mode. LANCommander's 2,000 and 2,500 locations were identical.
- The vulnerable app gained five NB and six project findings at 2,500 versus
  2,000, including Razor XSS/code-execution and archive extraction paths. Project
  mode also gained command-service findings. This is reported coverage, not a
  claim that every finding is a confirmed exploitable vulnerability.
- Sarifintown's extra finding is operator-selected workspace-path enumeration;
  the previous review established no privilege boundary. Its count alone is not
  a reason to raise the budget.
- All scans remained partial. Project mode exited 2 for incomplete analysis;
  Sarifintown had budget notices only. The vulnerable app additionally retained
  two NuGet vulnerability-audit workspace errors. LANCommander retained three
  npm/Aspire workspace errors and 108 compiler-error notices, versus 131 compiler
  notices in NB. NB retained package/reference/Razor coverage notices and exited 0
  under its existing partial-scan policy. No timeout or analyzer crash occurred.
- Cross-mode cutoff totals are not directly interchangeable: bindings and
  generated inputs differ, even when compilation counts match.
- Startup matters: the original vulnerable-app NB 1,000 run was 20.32 seconds,
  versus 6.62 on repeat. LANCommander's first NB 1,000 run was 58.58 seconds with
  28.00 seconds loading, versus 40.24 on repeat. Later NB loading was about seven
  seconds. These fluctuations must not be attributed to work-budget changes.

**Keep the shipped fast profile at 3/2,500.** In this batch it retained additional
reported paths for about 1.32 seconds more NB wall time across all three apps than
2,000. This comparison changes neither the CLI's default full profile nor any
rule, source/sink model or scope exclusion. See [cutoff families](cutoff-families.md)
for the tested improvements and discarded optimization experiments.
