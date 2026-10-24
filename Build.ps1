param([ValidateSet('Debug','Release')][string]$Configuration='Release',[switch]$AddressSanitizer)
$ErrorActionPreference='Stop'
$build=Join-Path $PSScriptRoot $(if($AddressSanitizer){'obj/Asan'}else{'obj/Build'})
& cmake -S $PSScriptRoot -B $build -G 'Visual Studio 17 2022' -A x64 "-DENABLE_ASAN=$($AddressSanitizer.IsPresent.ToString().ToUpperInvariant())"
if($LASTEXITCODE){throw 'CMake configuration failed.'}
& cmake --build $build --config $Configuration --parallel
if($LASTEXITCODE){throw 'C++ build failed.'}
# Report generation preserves existing files; give each test campaign a fresh path.
foreach($extension in 'json','html'){$old=Join-Path $build "preview-report-$Configuration.$extension";if(Test-Path -LiteralPath $old){$resolved=[IO.Path]::GetFullPath($old);if(-not $resolved.StartsWith([IO.Path]::GetFullPath($build)+[IO.Path]::DirectorySeparatorChar,[StringComparison]::OrdinalIgnoreCase)){throw 'Unexpected test report path.'};Remove-Item -LiteralPath $resolved}}
& ctest --test-dir $build -C $Configuration --output-on-failure
if($LASTEXITCODE){throw 'Offline validation failed.'}
