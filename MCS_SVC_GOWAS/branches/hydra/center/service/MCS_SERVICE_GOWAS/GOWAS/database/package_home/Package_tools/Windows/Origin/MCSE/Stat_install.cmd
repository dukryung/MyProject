@echo off
rem run this script as admin

set ProgName=%1

if not exist %ProgName%.exe (
    echo Build the %ProgName% before installing by running "go build"
    goto :exit
)

sc create %ProgName% binpath= "\"%CD%\%ProgName%.exe\" -l -p 9090" start= auto DisplayName= "%ProgName%"
sc description %ProgName% "%ProgName% Service"
sc start %ProgName%
echo Check excute.log

:exit