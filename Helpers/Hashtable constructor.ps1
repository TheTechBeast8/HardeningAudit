# Function to get a valid file path from the user
function Get-ValidFilePath {
    do {
        $filePath = Read-Host "Enter the full path to your 'All Registry Keys.txt' file"
        if (-not (Test-Path $filePath)) {
            Write-Host "File not found. Please enter a valid file path." -ForegroundColor Red
        }
    } while (-not (Test-Path $filePath))
    return $filePath
}

# Try to read the input file, prompt for a new path if it fails
try {
    $filePath = "C:\TOA\All Registry Keys.txt"  # Update this path as needed
    $content = Get-Content -Path $filePath -Raw -ErrorAction Stop
}
catch {
    Write-Host "Error: Unable to read file at $filePath" -ForegroundColor Red
    Write-Host "Let's try a different path." -ForegroundColor Yellow
    $filePath = Get-ValidFilePath
    $content = Get-Content -Path $filePath -Raw
}

# Split the content into sections
$sections = $content -split '(?m)^####.*####\s*$'

# Remove any empty sections
$sections = $sections | Where-Object { $_ -match '\S' }

# Initialize an empty array to store the hashtable strings
$hashtables = @()

foreach ($section in $sections) {
    $lines = $section -split "`n" | Where-Object { $_ -match '\S' }
    $sectionName = ($lines[0] -replace '^#', '').Trim()
    $hashtableName = "$" + $sectionName.Replace(" ", "")
    
    $hashtable = "@{`n"
    $currentPath = ""
    
    foreach ($line in $lines[1..$lines.Count]) {
        if ($line -match '^#') { continue }
        
        if ($line -match '^([^:]+):(.+)') {
            $regPath = $matches[1].Trim()
            $keyValue = $matches[2].Trim()
            
            # Split the key and value, but be careful with complex values
            $key = $keyValue -replace '^([^\s]+)\s+(.+)$', '$1'
            $value = $keyValue -replace '^([^\s]+)\s+(.+)$', '$2'
            
            if ($regPath -ne $currentPath) {
                if ($currentPath -ne "") {
                    $hashtable += "    }`n"
                }
                $currentPath = $regPath
                $hashtable += "    `"$regPath`" = @{`n"
            }
            
            # Handle special cases for the value
            if ($value -match '^(\d+)<x>') {
                $value = $matches[1]
            } elseif ($value -match '^\d+$') {
                # It's a number, don't add quotes
            } elseif ($value -eq '') {
                $value = '""'  # Empty string
            } elseif ($value -match '^{.*}$') {
                # It's already a complex value (like GUIDs), don't add extra quotes
                $value = "`"$value`""
            } else {
                # For other string values, ensure proper quoting
                $value = $value -replace '"', '`"'  # Escape any existing double quotes
                $value = "`"$value`""
            }
            
            $hashtable += "        `"$key`" = $value`n"
        }
    }
    
    if ($currentPath -ne "") {
        $hashtable += "    }`n"
    }
    
    $hashtable += "}"
    
    $hashtables += "$hashtableName = $hashtable`n"
}

# Output the hashtables
$output = $hashtables -join "`n"
Write-Output $output

# Ask user if they want to save the output to a file
$saveToFile = Read-Host "Do you want to save the output to a file? (Y/N)"
if ($saveToFile -eq 'Y' -or $saveToFile -eq 'y') {
    $outputPath = Read-Host "Enter the full path for the output file (e.g., C:\Output\output.ps1)"
    $output | Out-File -FilePath $outputPath
    Write-Host "Output saved to $outputPath" -ForegroundColor Green
}