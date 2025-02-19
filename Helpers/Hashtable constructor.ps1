$inputFilePath = "C:\TOA\All Registry Keys.txt"
function Convert-TextToHashtable {
    param (
        [string[]]$Lines
    )
    $result = [ordered]@{}
    $currentSection = $null
    foreach ($line in $Lines) {
        $line = $line.Trim()
        if (-not $line) { continue }
        if ($line.StartsWith('#') -and -not $line.StartsWith('##')) {
            $currentSection = $line.Substring(1)
            $result[$currentSection] = [ordered]@{}
        }
        elseif (-not $line.StartsWith('##') -and $currentSection) {
            $line = $line -replace '##.*$', ''  # Remove comments
            
            if ($line -match '^([^:]+):(.+?)\s+(.+)$') {
                $hivePath = $matches[1] -replace 'HKEY_LOCAL_MACHINE', 'HKLM'
                $keyName = $matches[2]
                $value = $matches[3].Trim('"')  # Remove quotes if present
                if (-not $result[$currentSection].Contains($hivePath)) {
                    $result[$currentSection][$hivePath] = [ordered]@{}
                }
                # Convert to integer if possible
                if ($value -match '^\d+$') {
                    $value = [int]$value
                }
                $result[$currentSection][$hivePath][$keyName] = $value
            }
        }
    }
    return $result
}
function Format-HashtableOutput {
    param (
        $Data
    )
    $output = @()
    foreach ($section in $Data.Keys) {
        $output += "`$$section = @{"
        foreach ($hivePath in $Data[$section].Keys) {
            $output += "    `"$hivePath`" = @{"
            foreach ($key in $Data[$section][$hivePath].Keys) {
                $value = $Data[$section][$hivePath][$key]
                if ($value -is [string]) {
                    $output += "        `"$key`" = `"$value`""
                } else {
                    $output += "        `"$key`" = $value"
                }
            }
            $output += "    }"
        }
        $output += "}"
    }
    return $output -join "`n"
}
# Main script logic
if (-not (Test-Path $InputFilePath)) {
    Write-Error "Input file not found: $InputFilePath"
    exit 1
}
$inputLines = Get-Content -Path $InputFilePath
$parsedData = Convert-TextToHashtable -Lines $inputLines
$formattedOutput = Format-HashtableOutput -Data $parsedData
Write-Output $formattedOutput