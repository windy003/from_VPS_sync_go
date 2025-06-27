go run main.go --create-config



go  run .\main.go  --config  .\vps_sync_config.json


start /B cmd /c "go run main.go --config vps_sync_config.json --background > out.txt 2>&1"

go build -o vps-sync-go.exe

./vps-sync.exe --config vps_sync_config.json