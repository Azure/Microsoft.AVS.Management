@ECHO OFF
SETLOCAL enableDelayedExpansion

CALL powershell.exe "%SYSTEM_DEFAULTWORKINGDIRECTORY%\build\build.ps1 %*"
IF "%ERRORLEVEL%" neq "0" (
    ECHO "----FAILED to run Powershell command. Exiting... ----"
    exit /b %ERRORLEVEL%
) ELSE (
    ECHO "---- build.cmd SUCCESSFUL!! ----"
)