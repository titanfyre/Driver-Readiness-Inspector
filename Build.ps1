param([ValidateSet('Debug','Release')][string]$Configuration='Release',[switch]$AddressSanitizer)
$ErrorActionPreference='Stop'
$vs=& "${env:ProgramFiles(x86)}\Microsoft Visual Studio\Installer\vswhere.exe" -latest -products * -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -property installationPath
if(!$vs){throw 'Visual Studio 2022 C++ desktop tools are required.'}
$toolsets=Get-ChildItem -LiteralPath (Join-Path $vs 'VC\Tools\MSVC') -Directory | Sort-Object {[version]$_.Name} -Descending
$toolset=$toolsets | Where-Object {(!$AddressSanitizer) -or ([version]$_.Name -ge [version]'14.38.0' -and (Test-Path -LiteralPath (Join-Path $_.FullName 'bin\Hostx64\x64\clang_rt.asan_dynamic-x86_64.dll')))} | Select-Object -First 1
if(!$toolset){throw 'Install the current Visual Studio C++ tools and AddressSanitizer component.'}
$savedPath=$env:PATH
$env:PATH=(Join-Path $toolset.FullName 'bin\Hostx64\x64')+';'+$env:PATH
$build=Join-Path $PSScriptRoot $(if($AddressSanitizer){'obj/Asan'}else{'obj/Build'})
try {
& cmake -S $PSScriptRoot -B $build -G 'Visual Studio 17 2022' -A x64 "-DENABLE_ASAN=$($AddressSanitizer.IsPresent.ToString().ToUpperInvariant())"
if($LASTEXITCODE){throw 'CMake configuration failed.'}
& cmake --build $build --config $Configuration --parallel -- ("/p:VCToolsVersion="+$toolset.Name) /p:PreferredToolArchitecture=x64
if($LASTEXITCODE){throw 'C++ build failed.'}
if($AddressSanitizer){Copy-Item -LiteralPath (Join-Path $toolset.FullName 'bin\Hostx64\x64\clang_rt.asan_dynamic-x86_64.dll') -Destination (Join-Path $build "bin\$Configuration") -Force}
Write-Host ('Compiler'+$(if($AddressSanitizer){' and ASAN runtime'}else{''})+': MSVC '+$toolset.Name)
# Report generation preserves existing files; give each test campaign a fresh path.
foreach($extension in 'json','html'){$old=Join-Path $build "preview-report-$Configuration.$extension";if(Test-Path -LiteralPath $old){$resolved=[IO.Path]::GetFullPath($old);if(-not $resolved.StartsWith([IO.Path]::GetFullPath($build)+[IO.Path]::DirectorySeparatorChar,[StringComparison]::OrdinalIgnoreCase)){throw 'Unexpected test report path.'};Remove-Item -LiteralPath $resolved}}
& ctest --test-dir $build -C $Configuration --output-on-failure
if($LASTEXITCODE){throw 'Offline validation failed.'}
} finally {$env:PATH=$savedPath}
