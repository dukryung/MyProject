@echo off
rem run this script as admin

set ProgName=%1

sc stop %ProgName%
sc delete %ProgName%