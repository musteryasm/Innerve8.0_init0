$logFilePath = "C:/Games/IIDS/alerts.json"

$alertsArray = @()

$currentDateTime = Get-Date

$fiveMinutesAgo = $currentDateTime.AddMinutes(-5)

$defenderAlerts = Get-WinEvent -LogName "Microsoft-Windows-Windows Defender/Operational" | 
                  Where-Object { $_.Id -eq 1116 -and $_.TimeCreated -ge $fiveMinutesAgo }

if ($defenderAlerts) {
    foreach ($alert in $defenderAlerts) {
        $timestamp = $alert.TimeCreated.ToString("MM/dd/yyyy HH:mm:ss")
        $message = $alert.Message | Out-String -Stream

        $name = ($message | Select-String 'Name: (.*)' | ForEach-Object { $_.Matches.Groups[1].Value }).Trim()
        $ID = ($message | Select-String 'ID: (.*)' | ForEach-Object { $_.Matches.Groups[1].Value }).Trim()
        $severity = ($message | Select-String 'Severity: (.*)' | ForEach-Object { $_.Matches.Groups[1].Value }).Trim()
        $category = ($message | Select-String 'Category: (.*)' | ForEach-Object { $_.Matches.Groups[1].Value }).Trim()
        $path = ($message | Select-String 'Path: (.*)' | ForEach-Object { $_.Matches.Groups[1].Value }).Trim()
        $detectionOrigin = ($message | Select-String 'Detection Origin: (.*)' | ForEach-Object { $_.Matches.Groups[1].Value }).Trim()
        $detectionType = ($message | Select-String 'Detection Type: (.*)' | ForEach-Object { $_.Matches.Groups[1].Value }).Trim()
        $detectionSource = ($message | Select-String 'Detection Source: (.*)' | ForEach-Object { $_.Matches.Groups[1].Value }).Trim()
        $user = ($message | Select-String 'User: (.*)' | ForEach-Object { $_.Matches.Groups[1].Value }).Trim()
        $processName = ($message | Select-String 'Process Name: (.*)' | ForEach-Object { $_.Matches.Groups[1].Value }).Trim()
        $securityIntelligenceVersion = ($message | Select-String 'Security intelligence Version: (.*)' | ForEach-Object { $_.Matches.Groups[1].Value }).Trim()
        $engineVersion = ($message | Select-String 'Engine Version: (.*)' | ForEach-Object { $_.Matches.Groups[1].Value }).Trim()
        $extractedMessage = ($message -split "`r`n" | Select-String 'Microsoft Defender Antivirus has detected malware or other potentially unwanted software.').Matches.Value

	$MACAddress = (Get-NetAdapter | Where-Object { $_.Status -eq 'Up' } | Select-Object -First 1).MACAddress

        $alertObject = @{
            "AlertTime" = $timestamp
            "AlertMessage" = @{
                "Message" = $extractedMessage
                "Name" = $name
                "ID" = $ID
                "Severity" = $severity
                "Category" = $category
                "Path" = $path
                "DetectionOrigin" = $detectionOrigin
                "DetectionType" = $detectionType
                "DetectionSource" = $detectionSource
                "User" = $user
                "ProcessName" = $processName
                "SecurityIntelligenceVersion" = $securityIntelligenceVersion
                "EngineVersion" = $engineVersion
		"MACAddress" = $MACAddress
            }
        }

        $alertsArray += $alertObject
    }

    $alertsJson = ConvertTo-Json -InputObject $alertsArray -Depth 100

    Set-Content -Path $logFilePath -Value $alertsJson

    $alertJson = ConvertTo-Json -InputObject $alertObject -Depth 100

    Set-Content -Path $logFilePath -Value $alertJson

    $apiUrl = "http://192.168.127.160:8000/api/receive_alert/"

    $headers = @{
        "Content-Type" = "application/json"
    }

    Invoke-WebRequest -Uri $apiUrl -Method POST -Headers $headers -Body $alertJson

}
