# Fail2BAn para Servidores Windows y en RDP
# @author Isaac Moran - Uniagro
# v.03052301

[xml]$CustomView=@"
<QueryList>
  <Query Id="0" Path="Security">
    <Select Path="Security">*[System[band(Keywords,4503599627370496) and TimeCreated[timediff(@SystemTime) &lt;= 10800000]]]</Select>
  </Query>
</QueryList>
"@
$WhiteList=@('127.0.0.1') #Estas IPs no se bloquean NUNCA
echo "Buscando en los logs accesos RDP fállidos..."
Get-WinEvent -FilterXML $CustomView | Export-CSV "C:\Utiles\datos_prefiltro$(Get-Date -format "yyyy-MM-dd").log"
echo "Filtrando IPs..."
Select-String -path "C:\Utiles\datos_prefiltro$(Get-Date -format "yyyy-MM-dd").log" -pattern "((\d{1,3}\.){3}\d{1,3})" | ForEach-Object { $_.Matches.Value } | sort | get-unique > "C:\Utiles\datos_postfiltro$(Get-Date -format "yyyy-MM-dd").log"
echo "Modificando regla del Firewal..."
[string[]]$ips=Get-Content -Path "C:\Utiles\datos_postfiltro$(Get-Date -format "yyyy-MM-dd").log"
# mirar que incluya ninguna en WhiteList
$ips= $ips | Where-Object { $WhiteList -notcontains $_ } 
Set-NetFirewallRule -DisplayName "BLOQUEO" -RemoteAddress $ips
rm "C:\Utiles\datos_prefiltro$(Get-Date -format "yyyy-MM-dd").log"
