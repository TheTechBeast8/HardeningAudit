#this script is to help with reporting script
#the enable scripts use nice easy hashtable since they are setting distinct values
#I needed to make something more to allow for checks of the values that have multiple correct configurations.
#this script converts hashtables to the more complex hashtables required for the reporting script
function Convert-HashtableToComparison {
    param (
        [hashtable]$inputHashTable
    )

    # Get the variable name from the call stack
    $variableName = '$comparisons' # Default value
    $callStack = Get-PSCallStack
    if ($callStack.Count -gt 1) {
        $callingCommand = $callStack[1].Position.Text
        if ($callingCommand -match '\$(\w+)') {
            $variableName = '$' + $matches[1]
        }
    }

    # Initialize the empty comparisons hashtable
    $comparisons = @{ }

    # Loop through the input hashtable and transform data
    foreach ($path in $inputHashTable.Keys) {
        $comparisonList = @()
        foreach ($key in $inputHashTable[$path].Keys) {
            $value = $inputHashTable[$path][$key]
            
            # Check if the value is a string or empty string and format it
            if ([string]::IsNullOrEmpty($value)) {
                $formattedValue = '""'  # For empty strings, output double quotes
            } elseif ($value -is [string]) {
                $formattedValue = "`"$value`""  # For non-empty strings, add quotes
            } else {
                $formattedValue = $value  # For non-string values, keep as is
            }

            # Add each transformed data to the $comparisonList
            $comparisonList += @{
                'key'   = $key
                'type'  = 'exact'
                'value' = $formattedValue
            }
        }

        # Assign the $comparisonList to the corresponding path in $comparisons
        $comparisons[$path] = $comparisonList
    }

    # Output the entire hashtable in a copyable format
    Write-Host "$variableName = @{"
    foreach ($path in $comparisons.Keys) {
        Write-Host "    '$path' = @("

        # Loop through the items and ensure the last item doesn't get a comma
        for ($i = 0; $i -lt $comparisons[$path].Count; $i++) {
            $item = $comparisons[$path][$i]
            $key = $item.key
            $valueType = $item.type
            $value = $item.value

            if ($i -eq ($comparisons[$path].Count - 1)) {
                Write-Host "        @{ 'key' = '$key'; 'type' = '$valueType'; 'value' = $value }"
            } else {
                Write-Host "        @{ 'key' = '$key'; 'type' = '$valueType'; 'value' = $value },"
            }
        }
        Write-Host "    )"
    }
    Write-Host "}"
}

# Call the function with the hashtables
Convert-HashtableToComparison -inputHashTable $L1Section1
Convert-HashtableToComparison -inputHashTable $L1Section2
Convert-HashtableToComparison -inputHashTable $L1Section5
Convert-HashtableToComparison -inputHashTable $L1Section9
Convert-HashtableToComparison -inputHashTable $L1Section18
Convert-HashtableToComparison -inputHashTable $L1Section19
Convert-HashtableToComparison -inputHashTable $L2Section2
Convert-HashtableToComparison -inputHashTable $L2Section5
Convert-HashtableToComparison -inputHashTable $L2Section18
Convert-HashtableToComparison -inputHashTable $L2Section19
Convert-HashtableToComparison -inputHashTable $SectionBitlocker
Convert-HashtableToComparison -inputHashTable $SectionNG
