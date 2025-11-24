export PATH="/media/araneta/49909430-d2bd-4bcf-be1d-3c425a4013bf/apps/go1.22/bin:$PATH"
#

#build debug
#go build main.go

#@build release linux 
go build -ldflags "-s -w"

#@build release win
#env GOOS=windows GOARCH=amd64 go build -ldflags "-s -w" -o "../../dist/goder.exe"
