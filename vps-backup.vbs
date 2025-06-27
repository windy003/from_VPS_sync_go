Set WshShell = CreateObject("WScript.Shell")
WshShell.Run "cmd /c ""go run main.go --config vps_sync_config.json --background >  vps_sync_log.txt 2>&1""", 0, False