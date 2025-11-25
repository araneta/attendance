export PATH="/home/aldo/apps/go/bin:$PATH"
#

#build debug
#go build main.go

#@build release linux 
go build -ldflags "-s -w"

#@build release win
#env GOOS=windows GOARCH=amd64 go build -ldflags "-s -w" -o "../../dist/goder.exe"
