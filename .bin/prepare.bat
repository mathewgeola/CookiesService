@echo off

for /f "tokens=1-3 delims=/- " %%a in ("%date%") do (
    set yyyy=%%a
    set mm=%%b
    set dd=%%c
)
for /f "tokens=1-2 delims=:." %%a in ("%time%") do (
    set hh=%%a
    set min=%%b
)

set hh=%hh: =0%

set message=%yyyy%/%mm%/%dd% %hh%:%min%

echo %message%

for /f %%i in ('git merge-base HEAD origin/main') do set BASE=%%i

git reset %BASE%

git add -A

git commit -m "%message%"
