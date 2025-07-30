go run main.go --create-config



go  run .\main.go  --config  .\vps_sync_config.json

<!-- 生成exe文件 -->
go build -ldflags="-H windowsgui"