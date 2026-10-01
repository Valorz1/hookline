Set-Location $PSScriptRoot
.\.venv\Scripts\python.exe -m pip install -q -r requirement.txt
.\.venv\Scripts\python.exe app.py
