@echo off

REM Compile the C source file
cl.exe /nologo /c /Od /MT /W0 /GS- /Tc hookdetector.c
REM Move the object file if needed
move /y hookdetector.obj hookdetector.o