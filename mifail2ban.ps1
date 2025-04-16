# Fail2Ban para Servidores Windows y en RDP
# @author Isaac Moran
# v.25041601
#
# Hay que generar una regla en el Firewall de Windows llamada "BLOQUEO" que rechaze todas las conexiones desde determinadas IPs
# el script se encargará de rellenar esa lista de IPs con la de los clientes que intenten hacer login fállido
#
if (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole("Administrator")) {
    Write-Error "Este script debe ejecutarse como administrador."
    exit
}

$PATH = (Split-Path $MyInvocation.MyCommand.Path -Parent) + "\"
$logPath = $PATH + "logs\"
if (!(Test-Path $logPath)) { New-Item -Path $logPath -ItemType Directory }
$ficheroWL=$PATH+"wl.log"
$ficheroLOG = $logPath + "log_$(Get-Date -format "yyyy-MM-dd").log"
$ficheroPREFILTRO = $logPath + "datos_prefiltro$(Get-Date -format "yyyy-MM-dd").log"
$ficheroPOSTFILTRO = $logPath + "datos_postfiltro$(Get-Date -format "yyyy-MM-dd").log"
$HorasBloqueo=6 #Las IPs que hayan intentando logar en estas últimas X horas son bloqueadas
$HorasWL=24 #Las IPs que hayan logado correctamente en estas últimas X horas van a WhiteList

# Nombre del origen personalizado para registrar los eventos
$origenEvento = "Fail2Ban-RDP"
$logEvento = "Application"

# Comprobar si el origen del evento ya existe
if (-not [System.Diagnostics.EventLog]::SourceExists($origenEvento)) {
    try {
        New-EventLog -LogName $logEvento -Source $origenEvento
        Write-Output "Origen de evento '$origenEvento' creado en el registro '$logEvento'"
    } catch {
        Write-Error "No se pudo crear el origen de evento. Ejecuta el script como administrador."
    }
}


#limpiar logs antiguos
Get-ChildItem -Path $logPath -File | Where-Object { $_.LastWriteTime -lt (Get-Date).AddDays(-15) } | Remove-Item

if (-not (Test-Path $ficheroWL)) {
    New-Item -Path $ficheroWL -ItemType File -Force | Out-Null
}

if (-not (Get-NetFirewallRule -DisplayName "BLOQUEO")) {
    Write-Error "La regla 'BLOQUEO' no existe. Créala manualmente antes de ejecutar este script."
    exit
}




# Query para buscar en el log del sistema los intentos de conexión fállidos de las últimas 6 horas
[xml]$VistaErrorLogin=@"
<QueryList>
  <Query Id="0" Path="Security">
    <Select Path="Security">*[System[band(Keywords,4503599627370496) and TimeCreated[timediff(@SystemTime) &lt;= $($HorasBloqueo*3600*1000)]]]</Select>
  </Query>
</QueryList>
"@
# Busca en el log del sistema los intentos de conexión exitosos de las últimas 24 horas
[xml]$VistaOKLogin=@"
<QueryList>
  <Query Id="0" Path="Security">
    <Select Path="Security">*[System[band(Keywords,9007199254740992) and (EventID=4648 or EventID=4778) and TimeCreated[timediff(@SystemTime) &lt;= $($HorasWL*3600*1000)]]]</Select>
  </Query>
</QueryList>
"@
Write-Output "Proceso iniciado $(Get-Date -format "dd-MM-yyyy HH:mm")" >> $ficheroLOG
$cadenaLog="Buscando en los logs accesos RDP correctos de las pasadas $HorasWL hora(s)..."
Write-Output $cadenaLog 
Write-Output $cadenaLog >> $ficheroLOG
Get-WinEvent -FilterXML $VistaOKLogin | Export-CSV $ficheroWL
$WhiteList=@('127.0.0.1') #Estas IPs no se bloquean NUNCA
[string[]]$WhiteList=Select-String -path $ficheroWL -pattern "((\d{1,3}\.){3}\d{1,3})" | ForEach-Object { $_.Matches.Value } | sort | get-unique
Remove-Item $ficheroWL
Write-Output "`nIPs no bloqueables:" >> $ficheroLOG
$WhiteList | Out-File -Append $ficheroLOG
$cadenaLog="Buscando en los logs accesos RDP con error de las pasadas $HorasBloqueo hora(s)..."
Write-Output $cadenaLog
Write-Output $cadenaLog >> $ficheroLOG
Get-WinEvent -FilterXML $VistaErrorLogin | Export-CSV $ficheroPREFILTRO
Write-Output "Filtrando IPs..."
Select-String -path $ficheroPREFILTRO -pattern "((\d{1,3}\.){3}\d{1,3})" | ForEach-Object { $_.Matches.Value } | sort | get-unique > $ficheroPOSTFILTRO
Write-Output "Modificando regla del Firewal..."
[string[]]$ips=Get-Content -Path $ficheroPOSTFILTRO
# mirar que incluya ninguna en WhiteList
$ips= $ips | Where-Object { $WhiteList -notcontains $_ } 
Write-Output "`nIPs a bloquear" >> $ficheroLOG
$ips | Out-File -Append $ficheroLOG
Set-NetFirewallRule -DisplayName "BLOQUEO" -RemoteAddress $ips
Remove-Item $ficheroPOSTFILTRO
Remove-Item $ficheroPREFILTRO
#logar eventos
if ($ips.Count -gt 0) {
    $mensajeEvento = "Se han bloqueado las siguientes IPs en la regla 'BLOQUEO': $($ips -join ', ')"
    Write-EventLog -LogName $logEvento -Source $origenEvento -EntryType Warning -EventId 1001 -Message $mensajeEvento
}
Write-Output "Fin proceso" >> $ficheroLOG
Write-Output "===================`n" >> $ficheroLOG
Write-Output "" >> $ficheroLOG
Write-Host "IPs bloqueadas exitosamente:" -ForegroundColor Green
$ips | ForEach-Object { Write-Host $_ -ForegroundColor Red }
