go run main.go --create-config



go  run .\main.go  --config  .\vps_sync_config.json

<!-- 生成exe文件 -->
go build -ldflags="-H windowsgui"

如果exe文件没有路标
重新运行:

rsrc  -ico 256x256.ico  -o  main.syso