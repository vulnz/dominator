' Launch Dominator GUI without console window
' Use this script to start the GUI cleanly

Set WshShell = CreateObject("WScript.Shell")
Set fso = CreateObject("Scripting.FileSystemObject")

' Get script directory
scriptDir = fso.GetParentFolderName(WScript.ScriptFullName)

' Find Python - try common locations
pythonwPath = ""

' Try pythonw.exe first (no console window)
If fso.FileExists("C:\Python312\pythonw.exe") Then
    pythonwPath = "C:\Python312\pythonw.exe"
ElseIf fso.FileExists("C:\Python311\pythonw.exe") Then
    pythonwPath = "C:\Python311\pythonw.exe"
ElseIf fso.FileExists("C:\Python310\pythonw.exe") Then
    pythonwPath = "C:\Python310\pythonw.exe"
Else
    ' Try to find pythonw from PATH
    Set objExec = WshShell.Exec("where pythonw.exe")
    pythonwPath = Trim(objExec.StdOut.ReadLine())
    If pythonwPath = "" Or InStr(pythonwPath, "not find") > 0 Then
        ' Fall back to python.exe
        Set objExec2 = WshShell.Exec("where python.exe")
        pythonwPath = Trim(objExec2.StdOut.ReadLine())
    End If
End If

If pythonwPath = "" Then
    MsgBox "Could not find Python. Please install Python and try again.", vbCritical, "Dominator"
    WScript.Quit 1
End If

' Launch GUI
mainPy = scriptDir & "\main.py"
WshShell.Run """" & pythonwPath & """ """ & mainPy & """ --gui", 0, False
