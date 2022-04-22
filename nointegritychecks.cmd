@echo off
bcdedit.exe /set {default} testsigning ON
bcdedit.exe /set {default} nointegritychecks ON
pause