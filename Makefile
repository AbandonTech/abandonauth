.PHONY: build
build: 
	sqlc generate
	go build cmd/abandonauth.go