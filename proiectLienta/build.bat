@echo off
echo Compilare proiect...
gcc antiviRus/antiviRus.c database/database.c workqueue/workqueue.c utils/utils.c -o antiviRus/antivirus.exe -lpsapi

if %errorlevel% equ 0 (
    echo ---------------------------------------
    echo Build REUSIT! Se porneste programul...
    echo ---------------------------------------
    cd antiviRus
    antiviRus.exe
    cd ..
) else (
    echo.
    echo ########## EROARE LA COMPILARE ##########
    echo Verifica erorile de mai sus.
)
pause