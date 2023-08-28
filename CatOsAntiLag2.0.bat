@ECHO OFF
TITLE CatOs AntiLag (Installer)
ECHO.
ECHO CatOs AntiLag!
ECHO ==========
ECHO.
ECHO Preparando Modificaciones...
SETLOCAL
REGEDIT /E %Temp%\tmp.reg "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\"

TYPE %Temp%\tmp.reg | FIND "{" > %Temp%\tmp2.reg

>%Temp%\add.reg ECHO Windows Registry Editor Version 5.00
>>%Temp%\add.reg ECHO.
>>%Temp%\add.reg ECHO [HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\MSMQ\Parameters]
>>%Temp%\add.reg ECHO "TCPNoDelay"=dword:00000001
>>%Temp%\add.reg ECHO.

FOR /F "tokens=*" %%i IN ('TYPE %Temp%\tmp2.reg') DO CALL :Parse %%i

ECHO Aplicando Tecnologias...

REGEDIT /S %Temp%\add.reg

:: Deshabilitar ventanas emergentes de notificación de Windows
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v EnableBalloonTips /t REG_DWORD /d 0 /f

:: Ajustar algunos parámetros de red
netsh interface tcp set global autotuning=disabled
netsh interface tcp set global rss=disabled
netsh interface tcp set global timestamps=disabled
netsh interface tcp set global initialrto=300
netsh interface tcp set global rsc=disabled
netsh interface tcp set global maxsynretransmissions=2
netsh interface tcp set global fastopen=disabled
netsh interface tcp set global fastopenfallback=disabled
netsh interface tcp set global hystart=disabled
netsh interface tcp set global prr=disabled
netsh interface tcp set global pacingprofile=off

:: Desactivar el escalado automático de Windows para monitores de alta resolución (opcional)
:: Esto puede mejorar la velocidad de renderización de elementos de la interfaz gráfica.
reg add "HKEY_CURRENT_USER\Control Panel\Desktop" /v LogPixels /t REG_DWORD /d 96 /f

:: Desactivar el mantenimiento automático de Windows (opcional)
:: Esto puede ayudar a reducir el uso de red en segundo plano.
schtasks /change /tn "\Microsoft\Windows\TaskScheduler\Maintenance Configurator" /disable

:: Deshabilitar el servicio Windows Update
sc config wuauserv start=disabled

:: Establecer la energía de la red Wi-Fi en máximo rendimiento
powercfg -setacvalueindex SCHEME_CURRENT SUB_WIFI 54e749fa-98e5-4efb-956b-175d777c54e3 1
powercfg -setactive SCHEME_CURRENT

ECHO Finalizando...

:: Reiniciar la red
netsh interface set interface "Ethernet" admin=disable
netsh interface set interface "Ethernet" admin=enable

ECHO Terminado !
ECHO No olvide darle las gracias a catmaster después de haber utilizado sus scripts ;)
ECHO Por favor, reinicie su máquina para aplicar los cambios.
ECHO CatOsAntiLag 2.0
ECHO.
pause
ENDLOCAL
GOTO:EOF

IF EXIST "%Temp%\tmp.reg" DEL "%Temp%\tmp.reg"
IF EXIST "%Temp%\tmp2.reg" DEL "%Temp%\tmp2.reg"
IF EXIST "%Temp%\add.reg" DEL "%Temp%\add.reg"

:Parse
SET Key=%1
>>%Temp%\add.reg ECHO %Key%
>>%Temp%\add.reg ECHO "TcpAckFrequency"=dword:00000001
>>%Temp%\add.reg ECHO.
GOTO:EOF
