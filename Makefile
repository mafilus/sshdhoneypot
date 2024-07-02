CC=go

all: sshd.go go.mod go.sum
	$(CC) build
