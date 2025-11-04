REM Disk Optimization, sfc, DISM, gpupdate, Disk Cleanup, scan for akira

@echo off

echo Running Disk Optimization...
defrag /C /O

echo.
echo Running System File Checker (sfc /scannow)...
sfc /scannow

echo.
echo Running Check Disk (chkdsk)...
chkdsk

echo.
echo Running DISM to Restore Health...
DISM /Online /Cleanup-Image /RestoreHealth

echo.
echo Updating Group Policy...
gpupdate /force

echo.
echo Running Disk Cleanup (cleanmgr /verylowdisk)...
cleanmgr /verylowdisk

echo.
echo Scan for akira...
cd..
cd..
dir *akira*.* /s

echo.
echo All commands have been executed.
pause