# fail2banRDP
Script Powershell para banear intentos de conexión fállidos por RDP a equipos/servidores Windows.
Inspirado en el mítico fail2Ban

## Instalación
1. Copiar el script en una carpeta del sistema
2. Personalizar los parámetros de las horas
3. Crear una regla en el Firewall de Windows llamada "BLOQUEO" que por defecto bloquee todas las conexiones de la lista de IPs
4. Configurar en el programador de tareas (tasksch) una tarea que se ejecute con la periodicidad deseada:
   `powershell -File <ruta_al_script>`
