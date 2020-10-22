@echo off
rem run this script as admin

set ProgName=%1

if not exist %ProgName%.exe (
    echo Build the %ProgName% before installing by running "go build"
    goto :exit
)

sc create %ProgName% binpath= "\"%CD%\%ProgName%.exe\" service=yes -f \"%CD%\cfg\app.cfg\"" start= auto DisplayName= "%ProgName%Service"
sc description %ProgName% "%ProgName% Networt Multi Stream Service"
sc start %ProgName%
sc query %ProgName%

echo Check service.log

:exit