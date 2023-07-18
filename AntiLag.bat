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

ECHO Finalizando...

IF EXIST "%Temp%\tmp.reg" DEL "%Temp%\tmp.reg"
IF EXIST "%Temp%\tmp2.reg" DEL "%Temp%\tmp2.reg"
IF EXIST "%Temp%\add.reg" DEL "%Temp%\add.reg"

ECHO Terminado !
ECHO No olvide darle las gracias a catmaster despues de haber utilizado sus scripts ;)
ECHO por favor reinicie su asquerosa , repugnante y horrible maquina.
ECHO.
PAUSE
ENDLOCAL
GOTO:EOF

:Parse
SET Key=%1
>>%Temp%\add.reg ECHO %Key%
>>%Temp%\add.reg ECHO "TcpAckFrequency"=dword:00000001
>>%Temp%\add.reg ECHO.
GOTO:EOF