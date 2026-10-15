# =====================================================================
#  J.A.R.V.I.S - Veille : serveur local (Windows PowerShell 5.1 / 7+)
#  - sert le site sur http://localhost:8765  (origine fixe => le navigateur
#    memorise l'autorisation du micro, plus de demande a chaque visite)
#  - recupere les flux RSS cote serveur (pas de probleme CORS, pas de proxy tiers)
#  Ecoute UNIQUEMENT sur localhost. Ctrl+C ou fermer la fenetre pour arreter.
# =====================================================================
param(
  [int]$Port = 8765,
  [switch]$NoBrowser
)

$ErrorActionPreference = 'Stop'
$Root = Split-Path -Parent $MyInvocation.MyCommand.Path
$Url  = "http://localhost:$Port/"

Add-Type -AssemblyName System.Net.Http
try {
  [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12 -bor [Net.SecurityProtocolType]'Tls13'
} catch {
  [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
}

# ---------- client HTTP partage ----------
$handler = New-Object System.Net.Http.HttpClientHandler
$handler.AutomaticDecompression = [System.Net.DecompressionMethods]::GZip -bor [System.Net.DecompressionMethods]::Deflate
$handler.AllowAutoRedirect = $true
$handler.MaxAutomaticRedirections = 5
$client = New-Object System.Net.Http.HttpClient($handler)
$client.Timeout = [TimeSpan]::FromSeconds(15)
[void]$client.DefaultRequestHeaders.TryAddWithoutValidation('User-Agent', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0 Safari/537.36')
[void]$client.DefaultRequestHeaders.TryAddWithoutValidation('Accept', 'application/rss+xml, application/atom+xml, application/xml;q=0.9, text/xml;q=0.9, text/html;q=0.8, */*;q=0.5')
[void]$client.DefaultRequestHeaders.TryAddWithoutValidation('Accept-Language', 'fr-FR,fr;q=0.9,en;q=0.8')

$MaxBody = 2MB

# ---------- securite : on ne relaie que vers des adresses publiques ----------
function Test-PublicIp([System.Net.IPAddress]$ip) {
  if ($ip.IsIPv4MappedToIPv6) { $ip = $ip.MapToIPv4() }
  if ([System.Net.IPAddress]::IsLoopback($ip)) { return $false }
  $b = $ip.GetAddressBytes()
  if ($ip.AddressFamily -eq [System.Net.Sockets.AddressFamily]::InterNetwork) {
    if ($b[0] -eq 10 -or $b[0] -eq 127 -or $b[0] -eq 0) { return $false }
    if ($b[0] -eq 172 -and $b[1] -ge 16 -and $b[1] -le 31) { return $false }
    if ($b[0] -eq 192 -and $b[1] -eq 168) { return $false }
    if ($b[0] -eq 169 -and $b[1] -eq 254) { return $false }
    if ($b[0] -eq 100 -and $b[1] -ge 64 -and $b[1] -le 127) { return $false }
    if ($b[0] -ge 224) { return $false }
    return $true
  }
  if ($ip.IsIPv6LinkLocal -or $ip.IsIPv6SiteLocal -or $ip.IsIPv6Multicast) { return $false }
  if (($b[0] -band 0xFE) -eq 0xFC) { return $false }
  return $true
}

# Resout tous les hotes en parallele et renvoie la liste des URL autorisees
function Get-AllowedUrls([string[]]$urls) {
  $ok = @{}
  $dns = @{}
  foreach ($u in $urls) {
    $uri = $null
    if (-not [Uri]::TryCreate($u, [UriKind]::Absolute, [ref]$uri)) { continue }
    if ($uri.Scheme -ne 'http' -and $uri.Scheme -ne 'https') { continue }
    if (-not $dns.ContainsKey($uri.DnsSafeHost)) { $dns[$uri.DnsSafeHost] = [System.Net.Dns]::GetHostAddressesAsync($uri.DnsSafeHost) }
  }
  if ($dns.Count -gt 0) {
    try { [void][System.Threading.Tasks.Task]::WaitAll([System.Threading.Tasks.Task[]]@($dns.Values), 6000) } catch {}
  }
  foreach ($u in $urls) {
    $uri = $null
    if (-not [Uri]::TryCreate($u, [UriKind]::Absolute, [ref]$uri)) { continue }
    $t = $dns[$uri.DnsSafeHost]
    if ($null -eq $t -or -not $t.IsCompleted -or $t.IsFaulted -or $t.IsCanceled) { continue }
    $addrs = $t.Result
    if ($addrs.Count -eq 0) { continue }
    $public = $true
    foreach ($a in $addrs) { if (-not (Test-PublicIp $a)) { $public = $false } }
    if ($public) { $ok[$u] = $true }
  }
  return $ok
}

# Decode le corps avec le bon jeu de caracteres (en-tete HTTP ou declaration XML/HTML)
function Read-Body($resp) {
  $bytes = $resp.Content.ReadAsByteArrayAsync().Result
  if ($bytes.Length -gt $MaxBody) { $tmp = New-Object byte[] $MaxBody; [Array]::Copy($bytes, $tmp, $MaxBody); $bytes = $tmp }
  $charset = $null
  try { $charset = $resp.Content.Headers.ContentType.CharSet } catch {}
  if (-not $charset) {
    $n = [Math]::Min(1024, $bytes.Length)
    $head = [System.Text.Encoding]::ASCII.GetString($bytes, 0, $n)
    $m = [regex]::Match($head, 'encoding=["'']([\w\-]+)["'']|charset=["'']?([\w\-]+)', 'IgnoreCase')
    if ($m.Success) { $charset = if ($m.Groups[1].Value) { $m.Groups[1].Value } else { $m.Groups[2].Value } }
  }
  $enc = [System.Text.Encoding]::UTF8
  if ($charset) { try { $enc = [System.Text.Encoding]::GetEncoding($charset.Trim('"')) } catch {} }
  $s = $enc.GetString($bytes)
  if ($s.Length -gt 0 -and $s[0] -eq [char]0xFEFF) { $s = $s.Substring(1) }
  return $s
}

# Serialisation JSON rapide et compatible PS 5.1 / 7
function ConvertTo-JsonFast($obj) {
  if ($PSVersionTable.PSVersion.Major -ge 6) { return (ConvertTo-Json -InputObject $obj -Depth 6 -Compress) }
  Add-Type -AssemblyName System.Web.Extensions
  $ser = New-Object System.Web.Script.Serialization.JavaScriptSerializer
  $ser.MaxJsonLength = [int]::MaxValue
  return $ser.Serialize($obj)
}

# Recupere plusieurs URL EN PARALLELE
function Get-Many([string[]]$urls) {
  $allowed = Get-AllowedUrls $urls
  $tasks = [ordered]@{}
  foreach ($u in $urls) { if ($allowed.ContainsKey($u) -and -not $tasks.Contains($u)) { $tasks[$u] = $client.GetAsync($u) } }
  if ($tasks.Count -gt 0) {
    try { [void][System.Threading.Tasks.Task]::WaitAll([System.Threading.Tasks.Task[]]@($tasks.Values), 16000) } catch {}
  }
  $out = New-Object System.Collections.Generic.List[object]
  foreach ($u in $urls) {
    $r = @{ url = $u; ok = $false; status = 0; body = ''; error = '' }
    if (-not $allowed.ContainsKey($u)) { $r.error = 'adresse refusee ou DNS introuvable' }
    elseif (-not $tasks.Contains($u)) { $r.error = 'doublon' }
    else {
      $t = $tasks[$u]
      if (-not $t.IsCompleted) { $r.error = 'delai depasse' }
      elseif ($t.IsFaulted -or $t.IsCanceled) {
        $e = if ($t.Exception) { $t.Exception.GetBaseException().Message } else { 'annule' }
        $r.error = $e
      } else {
        $resp = $t.Result
        $r.status = [int]$resp.StatusCode
        if ($resp.IsSuccessStatusCode) {
          try { $r.body = Read-Body $resp; $r.ok = $true } catch { $r.error = $_.Exception.Message }
        } else { $r.error = "HTTP $($r.status)" }
        $resp.Dispose()
      }
    }
    $out.Add($r)
  }
  return ,$out
}

# ---------- reponses ----------
$Mime = @{
  '.html' = 'text/html; charset=utf-8'; '.htm' = 'text/html; charset=utf-8'
  '.js' = 'text/javascript; charset=utf-8'; '.css' = 'text/css; charset=utf-8'
  '.json' = 'application/json; charset=utf-8'; '.webmanifest' = 'application/manifest+json; charset=utf-8'
  '.svg' = 'image/svg+xml'; '.png' = 'image/png'; '.jpg' = 'image/jpeg'; '.jpeg' = 'image/jpeg'
  '.ico' = 'image/x-icon'; '.webp' = 'image/webp'; '.txt' = 'text/plain; charset=utf-8'
}
function Send($ctx, [int]$code, [string]$type, $data) {
  $res = $ctx.Response
  $res.StatusCode = $code
  $res.ContentType = $type
  $res.Headers['Cache-Control'] = 'no-store'
  $res.Headers['X-Content-Type-Options'] = 'nosniff'
  if ($data -is [string]) { $bytes = [System.Text.Encoding]::UTF8.GetBytes($data) } else { $bytes = $data }
  $res.ContentLength64 = $bytes.Length
  $res.OutputStream.Write($bytes, 0, $bytes.Length)
}

function Handle($ctx) {
  $req = $ctx.Request
  $path = [Uri]::UnescapeDataString($req.Url.AbsolutePath)

  if ($path -eq '/api/ping') { Send $ctx 200 'application/json; charset=utf-8' '{"jarvis":true,"version":1}'; return }

  if ($path -eq '/api/feeds' -and $req.HttpMethod -eq 'POST') {
    $sr = New-Object System.IO.StreamReader($req.InputStream, [System.Text.Encoding]::UTF8)
    $json = $sr.ReadToEnd(); $sr.Close()
    $urls = @((ConvertFrom-Json $json).urls) | Where-Object { $_ } | Select-Object -First 150
    $sw = [Diagnostics.Stopwatch]::StartNew()
    $res = Get-Many ([string[]]$urls)
    $okc = @($res | Where-Object { $_.ok }).Count
    Write-Host ("  [{0}] {1}/{2} flux recuperes en {3:N1}s" -f (Get-Date -Format 'HH:mm:ss'), $okc, $urls.Count, $sw.Elapsed.TotalSeconds) -ForegroundColor Cyan
    Send $ctx 200 'application/json; charset=utf-8' (ConvertTo-JsonFast $res)
    return
  }

  if ($path -eq '/api/proxy') {
    $u = $req.QueryString['url']
    $res = Get-Many @([string]$u)
    $r = $res[0]
    if ($r.ok) { Send $ctx 200 'text/plain; charset=utf-8' $r.body }
    else { Send $ctx 502 'text/plain; charset=utf-8' ("Erreur : " + $r.error) }
    return
  }

  # fichiers statiques
  if ($path -eq '/' -or $path -eq '') { $path = '/index.html' }
  $full = [IO.Path]::GetFullPath((Join-Path $Root ($path.TrimStart('/') -replace '/', [IO.Path]::DirectorySeparatorChar)))
  $rootSep = $Root.TrimEnd([IO.Path]::DirectorySeparatorChar) + [IO.Path]::DirectorySeparatorChar
  if (-not $full.StartsWith($rootSep, [StringComparison]::OrdinalIgnoreCase) -or -not (Test-Path -LiteralPath $full -PathType Leaf)) {
    Send $ctx 404 'text/plain; charset=utf-8' 'Introuvable'; return
  }
  $ext = [IO.Path]::GetExtension($full).ToLower()
  $type = if ($Mime.ContainsKey($ext)) { $Mime[$ext] } else { 'application/octet-stream' }
  Send $ctx 200 $type ([IO.File]::ReadAllBytes($full))
}

# ---------- demarrage ----------
$listener = New-Object System.Net.HttpListener
$listener.Prefixes.Add($Url)
try { $listener.Start() }
catch {
  Write-Host "Le port $Port est deja utilise : Jarvis tourne sans doute deja. Ouverture du navigateur..." -ForegroundColor Yellow
  if (-not $NoBrowser) { Start-Process $Url }
  Start-Sleep -Seconds 3
  exit 0
}

try { $host.UI.RawUI.WindowTitle = 'J.A.R.V.I.S - Veille (serveur local)' } catch {}
Write-Host ''
Write-Host '   J.A.R.V.I.S  //  VEILLE CYBER' -ForegroundColor Cyan
Write-Host "   En ligne sur $Url" -ForegroundColor Green
Write-Host '   Laisse cette fenetre ouverte. Ctrl+C pour arreter.' -ForegroundColor DarkGray
Write-Host ''
if (-not $NoBrowser) { Start-Process $Url }

try {
  while ($listener.IsListening) {
    $task = $listener.GetContextAsync()
    while (-not $task.AsyncWaitHandle.WaitOne(250)) { }
    $ctx = $task.GetAwaiter().GetResult()
    try { Handle $ctx }
    catch {
      Write-Host ("  ! " + $_.Exception.Message) -ForegroundColor Red
      try { Send $ctx 500 'text/plain; charset=utf-8' 'Erreur serveur' } catch {}
    }
    finally { try { $ctx.Response.OutputStream.Close() } catch {} }
  }
} finally {
  $listener.Stop(); $listener.Close(); $client.Dispose()
}
