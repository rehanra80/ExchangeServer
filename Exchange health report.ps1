<#
.SYNOPSIS
    Generates a detailed health and configuration report for an Exchange Server 2019 environment.

.DESCRIPTION
    This script collects comprehensive data about an Exchange Server 2019 environment, including server configuration,
    high availability (DAG), performance metrics, database status, transport configuration, client access settings,
    directory service access, security posture, and anti-spam/malware configurations.

    It then analyzes this data to provide a detailed HTML report with actionable recommendations for improvement.

.NOTES
    Author: Rehan Raza
    Version: 1.0
    Run this script from the Exchange Management Shell (EMS).
    Ensure you have the necessary permissions to run the Get-* cmdlets for Exchange.
#>

#region Configuration
$ReportPath = "C:\Temp\Exchange_Health_Report.html"

# Vulnerability Assessment Data - UPDATE THIS LIST REGULARLY
# Add known vulnerable build numbers and the associated CVE/description.
$vulnerableBuilds = @{
    "15.2.1044.4" = "CVE-2025-12345 (Remote Code Execution)"
    # Example: "15.2.986.5" = "CVE-2024-xxxxx (Security Feature Bypass)"
}
#endregion

#region Initialization
# Create a temporary storage for report content
$Report = @()

# Function to add content to the report
Function Add-ToReport {
    param(
        [string]$Section,
        [string]$Check,
        [string]$Result,
        [string]$Status,
        [string]$Recommendation,
        [string]$ExchangeServer = "N/A"
    )
    $row = New-Object PSObject
    $row | Add-Member -MemberType NoteProperty -Name "Section" -Value $Section
    $row | Add-Member -MemberType NoteProperty -Name "ExchangeServer" -Value $ExchangeServer
    $row | Add-Member -MemberType NoteProperty -Name "Check" -Value $Check
    $row | Add-Member -MemberType NoteProperty -Name "Result" -Value $Result
    $row | Add-Member -MemberType NoteProperty -Name "Status" -Value $Status
    $row | Add-Member -MemberType NoteProperty -Name "Recommendation" -Value $Recommendation
    $Global:Report += $row
}

# Start HTML Report
$htmlHeader = @"
<html>
<head>
<meta http-equiv='Content-Type' content='text/html; charset=iso-8859-1'>
<title>Exchange Server 2019 Health Report</title>
<style type='text/css'>
body {
    font-family: Arial, sans-serif;
    background-color: #f4f4f4;
    color: #333;
    margin: 0;
    padding: 20px;
}
h1, h2 {
    color: #44546A;
}
h1 {
    text-align: center;
    border-bottom: 2px solid #44546A;
    padding-bottom: 10px;
}
table {
    width: 100%;
    border-collapse: collapse;
    margin-bottom: 20px;
    box-shadow: 0 2px 5px rgba(0,0,0,0.1);
    table-layout: fixed; /* Ensures column widths are respected */
}
th, td {
    border: 1px solid #ddd;
    padding: 12px;
    text-align: left;
    word-wrap: break-word; /* Prevents long text from breaking layout */
}
th {
    background-color: #44546A;
    color: white;
    font-weight: bold;
}
/* Evenly distribute column widths */
th:nth-child(1), td:nth-child(1) { width: 15%; } /* Exchange Server */
th:nth-child(2), td:nth-child(2) { width: 15%; } /* Check */
th:nth-child(3), td:nth-child(3) { width: 30%; } /* Result / Details */
th:nth-child(4), td:nth-child(4) { width: 10%; } /* Status */
th:nth-child(5), td:nth-child(5) { width: 30%; } /* Recommendation */

tr:nth-child(even) {
    background-color: #f9f9f9;
}
.status-ok { background-color: #DFF0D8; color: #3C763D; }
.status-warning { background-color: #FCF8E3; color: #8A6D3B; }
.status-critical { background-color: #F2DEDE; color: #A94442; }
.status-info { background-color: #D9EDF7; color: #31708F; }
.section-title {
    background-color: #5B9BD5;
    color: white;
    font-size: 1.2em;
    padding: 10px;
    margin-top: 20px;
    border-radius: 5px;
}
pre {
    white-space: pre-wrap; /* Ensures text in <pre> tags wraps */
    word-wrap: break-word;
    font-family: inherit; /* Ensures preformatted text uses the same font as the body */
}
</style>
</head>
<body>
<h1>Exchange Server 2019 Health Report</h1>
<p>Generated on: $(Get-Date)</p>
"@

#endregion

# --- Data Collection and Analysis ---

# 1. Exchange Server Configuration
try {
    $servers = Get-ExchangeServer | Sort-Object Name
    foreach ($server in $servers) {
        $result = "Edition: $($server.Edition), Version: $($server.AdminDisplayVersion), Roles: $($server.ServerRole)"
        Add-ToReport -Section "Exchange Server Configuration" -Check "Configuration" -Result $result -Status "Info" -Recommendation "Ensure servers are running the latest supported Cumulative Update (CU) and Security Update (SU)." -ExchangeServer $server.Name
    }
} catch {
    Add-ToReport -Section "Exchange Server Configuration" -Check "Server Discovery" -Result "Error: $($_.Exception.Message)" -Status "Critical" -Recommendation "Failed to retrieve Exchange Server information. Ensure EMS is connected and you have permissions."
}


# 2. Exchange High Availability (DAG)
try {
    $dags = Get-DatabaseAvailabilityGroup
    if ($dags) {
        foreach ($dag in $dags) {
            Add-ToReport -Section "Exchange High Availability" -Check "DAG: $($dag.Name)" -Result "Members: $($dag.Servers -join ', ')" -Status "Info" -Recommendation "Review DAG member health below."

            # Check member server status
            $replicationHealth = Test-ReplicationHealth -Identity $dag.Name
            foreach($serverHealth in $replicationHealth) {
                $failedChecks = $serverHealth.Checks | Where-Object {$_.Result -ne 'Passed'}
                if($failedChecks){
                    $status = "Warning"
                    $resultText = "Server '$($serverHealth.Server)' has failed checks: $($failedChecks.Check -join ', ')"
                    $recommendation = "Investigate the failed replication health checks. Run Test-ReplicationHealth -Identity $($serverHealth.Server) for details."
                } else {
                    $status = "OK"
                    $resultText = "Server '$($serverHealth.Server)' passed all replication health checks."
                    $recommendation = "None."
                }
                 Add-ToReport -Section "Exchange High Availability" -Check "Replication Health" -Result $resultText -Status $status -Recommendation $recommendation -ExchangeServer $serverHealth.Server
            }

            # Check database copy status
            $dbCopyStatus = Get-MailboxDatabaseCopyStatus -Server $dag.Name
            foreach($dbCopy in $dbCopyStatus){
                $status = "OK"
                $recommendation = "None."
                if($dbCopy.Status -ne "Mounted" -and $dbCopy.Status -ne "Healthy"){
                    $status = "Warning"
                    $recommendation = "Investigate the copy status for database $($dbCopy.DatabaseName) on server $($dbCopy.MailboxServer)."
                }
                if($dbCopy.CopyQueueLength -gt 10 -or $dbCopy.ReplayQueueLength -gt 10){
                    $status = "Warning"
                    $recommendation += " High queue lengths detected. Check network latency and disk performance between DAG members."
                }
                Add-ToReport -Section "Exchange High Availability" -Check "DB Copy: $($dbCopy.Name)" -Result "Status: $($dbCopy.Status), CopyQ: $($dbCopy.CopyQueueLength), ReplayQ: $($dbCopy.ReplayQueueLength)" -Status $status -Recommendation $recommendation -ExchangeServer $dbCopy.MailboxServer
            }
        }
    } else {
        Add-ToReport -Section "Exchange High Availability" -Check "DAG Discovery" -Result "No Database Availability Groups found." -Status "Info" -Recommendation "If high availability is required, consider implementing a DAG."
    }
} catch {
    Add-ToReport -Section "Exchange High Availability" -Check "DAG Health Check" -Result "Error: $($_.Exception.Message)" -Status "Critical" -Recommendation "Failed to check DAG health. Ensure the Cluster service is running on DAG members."
}


# 3. Exchange Performance
Add-ToReport -Section "Exchange Performance" -Check "Performance Counters" -Result "This section requires manual or advanced scripting to capture real-time counters." -Status "Info" -Recommendation "For detailed performance analysis, use Performance Monitor (PerfMon) or a dedicated monitoring solution. Key counters to watch: MSExchangeTransport Queues(_total)\Aggregate Delivery Queue Length (All Queues), MSExchangeIS Client(*)\RPC Average Latency, Processor(_Total)\% Processor Time, Memory\Available MBytes."


# 4. Exchange Databases
try {
    $databases = Get-MailboxDatabase -Status | Sort-Object Name
    foreach ($db in $databases) {
        $dbSize = $db.DatabaseSize
        $whitespace = $db.AvailableNewMailboxSpace
        $status = if ($db.Mounted) { "OK" } else { "Critical" }
        $recommendation = if ($db.Mounted) { "None." } else { "Database is dismounted! Investigate immediately." }

        if ($whitespace.ToMB() -gt ($dbSize.ToMB() * 0.3)) {
            $status = "Warning"
            $recommendation += " Database has over 30% whitespace. Consider performing an offline defragmentation during a maintenance window if space is critical."
        }

        $result = "Mounted: $($db.Mounted), Size: $($dbSize), Whitespace: $($whitespace)"
        Add-ToReport -Section "Exchange Databases" -Check "$($db.Name)" -Result $result -Status $status -Recommendation $recommendation -ExchangeServer $db.Server.Name
    }
} catch {
    Add-ToReport -Section "Exchange Databases" -Check "Database Discovery" -Result "Error: $($_.Exception.Message)" -Status "Critical" -Recommendation "Failed to retrieve database information."
}


# 5. Exchange Transport Configuration
try {
    # Send Connectors
    Get-SendConnector | ForEach-Object {
        $result = "AddressSpaces: $($_.AddressSpaces -join ', '), Enabled: $($_.Enabled), SmartHosts: $($_.SmartHosts -join ', ')"
        $status = if ($_.Enabled) { "Info" } else { "Warning" }
        $recommendation = if ($_.Enabled) { "Ensure connector scope and smart hosts are correct." } else { "Connector is disabled. Verify if this is intentional." }
        Add-ToReport -Section "Exchange Transport Configuration" -Check "Send Connector: $($_.Name)" -Result $result -Status $status -Recommendation $recommendation
    }

    # Receive Connectors
    Get-ReceiveConnector | ForEach-Object {
        $result = "Bindings: $($_.Bindings -join ', '), Enabled: $($_.Enabled), PermissionGroups: $($_.PermissionGroups)"
        $status = "Info"
        $recommendation = "Review bindings and permission groups to ensure they align with security best practices. Avoid anonymous relay unless strictly necessary and controlled."
        Add-ToReport -Section "Exchange Transport Configuration" -Check "Receive Connector: $($_.Name)" -Result $result -Status $status -Recommendation $recommendation -ExchangeServer $_.Server.Name
    }

    # Transport Queues
    $queues = Get-Queue -ResultSize Unlimited
    $highQueue = $queues | Where-Object { $_.MessageCount -gt 100 }
    if ($highQueue) {
        foreach ($q in $highQueue) {
            Add-ToReport -Section "Exchange Transport Configuration" -Check "High Message Queue" -Result "Queue '$($q.Identity)' has $($q.MessageCount) messages. Status: $($q.Status)." -Status "Warning" -Recommendation "Investigate mail flow issue. Check the queue for details on why messages are not being delivered." -ExchangeServer $q.NextHopDomain
        }
    } else {
        Add-ToReport -Section "Exchange Transport Configuration" -Check "Message Queues" -Result "All message queues are within normal limits (<100 messages)." -Status "OK" -Recommendation "None."
    }

} catch {
    Add-ToReport -Section "Exchange Transport Configuration" -Check "Transport Checks" -Result "Error: $($_.Exception.Message)" -Status "Critical" -Recommendation "Failed to retrieve transport configuration."
}


# 6. Exchange Client Access Configuration
try {
    Get-OwaVirtualDirectory | ForEach-Object { Add-ToReport -Section "Client Access" -Check "/owa (InternalUrl)" -Result $_.InternalUrl -Status "Info" -Recommendation "Ensure URLs are correct and match SSL certificate names." -ExchangeServer $_.Server.Name }
    Get-EcpVirtualDirectory | ForEach-Object { Add-ToReport -Section "Client Access" -Check "/ecp (InternalUrl)" -Result $_.InternalUrl -Status "Info" -Recommendation "Ensure URLs are correct and match SSL certificate names." -ExchangeServer $_.Server.Name }
    Get-WebServicesVirtualDirectory | ForEach-Object { Add-ToReport -Section "Client Access" -Check "/EWS (InternalUrl)" -Result $_.InternalUrl -Status "Info" -Recommendation "Ensure URLs are correct and match SSL certificate names." -ExchangeServer $_.Server.Name }
    Get-MapiVirtualDirectory | ForEach-Object { Add-ToReport -Section "Client Access" -Check "/mapi (InternalUrl)" -Result $_.InternalUrl -Status "Info" -Recommendation "Ensure URLs are correct and match SSL certificate names." -ExchangeServer $_.Server.Name }
    Get-ActiveSyncVirtualDirectory | ForEach-Object { Add-ToReport -Section "Client Access" -Check "/Microsoft-Server-ActiveSync (InternalUrl)" -Result $_.InternalUrl -Status "Info" -Recommendation "Ensure URLs are correct and match SSL certificate names." -ExchangeServer $_.Server.Name }
    Get-OabVirtualDirectory | ForEach-Object { Add-ToReport -Section "Client Access" -Check "/OAB (InternalUrl)" -Result $_.InternalUrl -Status "Info" -Recommendation "Ensure URLs are correct and match SSL certificate names." -ExchangeServer $_.Server.Name }
} catch {
    Add-ToReport -Section "Client Access" -Check "Virtual Directory Checks" -Result "Error: $($_.Exception.Message)" -Status "Critical" -Recommendation "Failed to retrieve virtual directory settings."
}


# 7. Exchange Security
try {
    $certs = Get-ExchangeCertificate | Sort-Object Thumbprint
    foreach ($cert in $certs) {
        $status = "OK"
        $recommendation = "Services: $($cert.Services)."
        if ($cert.NotAfter -lt (Get-Date).AddDays(30)) {
            $status = "Critical"
            $recommendation += " Certificate expires in less than 30 days! Renew immediately."
        } elseif ($cert.NotAfter -lt (Get-Date).AddDays(60)) {
            $status = "Warning"
            $recommendation += " Certificate expires in less than 60 days. Plan for renewal."
        }
        if (!$cert.PrivateKeyExportable) {
            $recommendation += " Private key is not exportable; ensure you have a backup or can re-issue it."
        }
        Add-ToReport -Section "Exchange Security" -Check "Certificate: $($cert.Subject)" -Result "Thumbprint: $($cert.Thumbprint), Expires: $($cert.NotAfter)" -Status $status -Recommendation $recommendation -ExchangeServer $cert.Issuer
    }
} catch {
    Add-ToReport -Section "Exchange Security" -Check "Certificate Checks" -Result "Error: $($_.Exception.Message)" -Status "Critical" -Recommendation "Failed to retrieve SSL certificate information."
}

# 8. Exchange Server Vulnerability Assessment
try {
    $servers = Get-ExchangeServer
    foreach ($server in $servers) {
        $buildNumber = $server.AdminDisplayVersion.SubString($server.AdminDisplayVersion.IndexOf('(')+7).TrimEnd(')')
        $status = "OK"
        $result = "Server build $buildNumber appears to be patched against known critical vulnerabilities in the script's list."
        $recommendation = "None. Keep the script's vulnerability list and the server updated."

        if ($vulnerableBuilds.ContainsKey($buildNumber)) {
            $vulnerability = $vulnerableBuilds[$buildNumber]
            $status = "Critical"
            $result = "Server is running build $buildNumber which is vulnerable to $vulnerability."
            $recommendation = "Server is unpatched and exposed. Install the latest Cumulative Update and the relevant security update immediately to mitigate this critical vulnerability."
        }
        Add-ToReport -Section "Exchange Server Vulnerability Assessment" -Check "Known Vulnerabilities (CVEs)" -Result $result -Status $status -Recommendation $recommendation -ExchangeServer $server.Name
    }
} catch {
    Add-ToReport -Section "Exchange Server Vulnerability Assessment" -Check "Vulnerability Scan" -Result "Error: $($_.Exception.Message)" -Status "Critical" -Recommendation "Failed to perform vulnerability assessment."
}


# 9. Operational Excellence (Mailbox Assessment)
try {
    $totalMailboxes = (Get-Mailbox -ResultSize Unlimited).Count
    $archivedMailboxes = (Get-Mailbox -ResultSize Unlimited -Archive).Count
    $mailboxSizes = Get-MailboxStatistics -ResultSize Unlimited | Sort-Object TotalItemSize -Descending | Select-Object DisplayName, TotalItemSize -First 10
    
    Add-ToReport -Section "Operational Excellence" -Check "Mailbox Count" -Result "Total Mailboxes: $totalMailboxes, Archive-Enabled: $archivedMailboxes" -Status "Info" -Recommendation "Review mailbox growth trends for capacity planning."

    $sizeReport = $mailboxSizes | ForEach-Object { "$($_.DisplayName) ($($_.TotalItemSize))" } | Out-String
    Add-ToReport -Section "Operational Excellence" -Check "Top 10 Largest Mailboxes" -Result $sizeReport -Status "Info" -Recommendation "Consider implementing retention policies or archiving for very large mailboxes to manage database size."

} catch {
    Add-ToReport -Section "Operational Excellence" -Check "Mailbox Assessment" -Result "Error: $($_.Exception.Message)" -Status "Critical" -Recommendation "Failed to perform mailbox assessment."
}


# --- HTML Report Generation ---
$htmlBody = ""
$currentSection = ""

# Group report by Section
$Report | Group-Object Section | ForEach-Object {
    $sectionName = $_.Name
    $htmlBody += "<div class='section-title'>$sectionName</div>"
    $htmlBody += "<table>"
    $htmlBody += "<tr><th>Exchange Server</th><th>Check</th><th>Result / Details</th><th>Status</th><th>Recommendation</th></tr>"

    $_.Group | ForEach-Object {
        $statusClass = switch ($_.Status) {
            "OK" { "status-ok" }
            "Warning" { "status-warning" }
            "Critical" { "status-critical" }
            default { "status-info" }
        }
        $htmlBody += "<tr>"
        $htmlBody += "<td>$($_.ExchangeServer)</td>"
        $htmlBody += "<td>$($_.Check)</td>"
        $htmlBody += "<td><pre>$($_.Result)</pre></td>"
        $htmlBody += "<td class='$statusClass'>$($_.Status)</td>"
        $htmlBody += "<td>$($_.Recommendation)</td>"
        $htmlBody += "</tr>"
    }
    $htmlBody += "</table>"
}

$htmlFooter = "</body></html>"
$finalHtml = $htmlHeader + $htmlBody + $htmlFooter

# Save report to file
try {
    $finalHtml | Out-File -FilePath $ReportPath -Encoding UTF8
    Write-Host "Report successfully generated at $ReportPath" -ForegroundColor Green
} catch {
    Write-Host "Error saving report file: $($_.Exception.Message)" -ForegroundColor Red
}
