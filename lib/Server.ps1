# Minimal local HTTP server for the report dashboard.
# Serves the generated report over http://localhost:<port>/ and opens the
# default browser. If the HTTP listener cannot bind (permissions/ACL), it falls
# back to opening the report file directly.

function Start-ReportServer {
    param(
        [Parameter(Mandatory)][string]$HtmlPath,
        [Parameter(Mandatory)][string]$JsonPath,
        [switch]$NoBrowser,
        [int]$Port = 0
    )

    if ($Port -eq 0) {
        # Pick a free ephemeral port.
        $l = [System.Net.Sockets.TcpListener]::new([System.Net.IPAddress]::Loopback, 0)
        $l.Start(); $Port = $l.LocalEndpoint.Port; $l.Stop()
    }

    $prefix = "http://localhost:$Port/"
    $listener = $null
    try {
        $listener = [System.Net.HttpListener]::new()
        $listener.Prefixes.Add($prefix)
        $listener.Start()
    }
    catch {
        Write-Host "  Could not start local web server ($($_.Exception.Message))." -ForegroundColor Yellow
        Write-Host "  Opening the report file directly instead." -ForegroundColor Yellow
        if (-not $NoBrowser) { Start-Process $HtmlPath }
        return
    }

    $url = "$prefix"
    Write-Host ""
    Write-Host "  +-----------------------------------------------------------+" -ForegroundColor Cyan
    Write-Host "  |  WinSecAudit dashboard is live                            |" -ForegroundColor Cyan
    Write-Host ("  |  {0,-57}|" -f $url) -ForegroundColor Cyan
    Write-Host "  |  Press Ctrl+C to stop the server.                         |" -ForegroundColor Cyan
    Write-Host "  +-----------------------------------------------------------+" -ForegroundColor Cyan
    Write-Host ""

    if (-not $NoBrowser) { Start-Process $url }

    $html = Get-Content -Path $HtmlPath -Raw -Encoding UTF8
    $json = Get-Content -Path $JsonPath -Raw -Encoding UTF8
    $htmlBytes = [System.Text.Encoding]::UTF8.GetBytes($html)
    $jsonBytes = [System.Text.Encoding]::UTF8.GetBytes($json)

    try {
        while ($listener.IsListening) {
            $ctx = $listener.GetContext()
            $req = $ctx.Request
            $res = $ctx.Response
            $path = $req.Url.AbsolutePath.ToLower()

            if ($path -eq '/report.json') {
                $res.ContentType = 'application/json; charset=utf-8'
                $res.ContentLength64 = $jsonBytes.Length
                $res.OutputStream.Write($jsonBytes, 0, $jsonBytes.Length)
            }
            else {
                $res.ContentType = 'text/html; charset=utf-8'
                $res.ContentLength64 = $htmlBytes.Length
                $res.OutputStream.Write($htmlBytes, 0, $htmlBytes.Length)
            }
            $res.OutputStream.Close()
        }
    }
    finally {
        if ($listener -and $listener.IsListening) { $listener.Stop() }
        if ($listener) { $listener.Close() }
    }
}
