@ECHO OFF
SETLOCAL

SET PYTHONPATH="../..:%PYTHONPATH%"
C:\python27\python.exe -m sllurp.decode %*

ENDLOCAL
