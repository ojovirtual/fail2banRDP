# Fail2Ban para Servidores Windows y en RDP
# @author Isaac Moran - @ojovirtual
# v.23092401
#
# Hay que generar una regla en el Firewall de Windows llamada "BLOQUEO" que rechaze todas las conexiones desde determinadas IPs
# el script se encargará de rellenar esa lista de IPs con la de los clientes que intenten hacer login fállido
#
$PATH = (Split-Path $MyInvocation.MyCommand.Path -Parent) + "\"
$ficheroWL=$PATH+"wl.log"
$ficheroLOG=$PATH+"log_$(Get-Date -format "yyyy-MM-dd").log"
$ficheroPREFILTRO=$PATH+"datos_prefiltro$(Get-Date -format "yyyy-MM-dd").log"
$ficheroPOSTFILTRO=$PATH+"datos_postfiltro$(Get-Date -format "yyyy-MM-dd").log"
$HorasBloqueo=6 #Las IPs que hayan intentando logar en estas últimas X horas son bloqueadas
$HorasWL=24 #Las IPs que hayan logado correctamente en estas últimas X horas van a WhiteList

# Query para buscar en el log del sistema los intentos de conexión fállidos de las últimas horas
[xml]$VistaErrorLogin=@"
<QueryList>
  <Query Id="0" Path="Security">
    <Select Path="Security">*[System[band(Keywords,4503599627370496) and TimeCreated[timediff(@SystemTime) &lt;= $($HorasBloqueo*3600*1000)]]]</Select>
  </Query>
</QueryList>
"@
# Busca en el log del sistema los intentos de conexión exitosos de las últimas horas
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
Write-Output "Fin proceso" >> $ficheroLOG
Write-Output "===================`n" >> $ficheroLOG
Write-Output "" >> $ficheroLOG
