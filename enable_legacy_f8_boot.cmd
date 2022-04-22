@echo off
bcdedit /set {default} bootmenupolicy legacy
bcdedit /set {bootmgr} displaybootmenu yes
bcdedit /timeout 12
pause