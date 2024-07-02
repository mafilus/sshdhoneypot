package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"os"

	"golang.org/x/crypto/ssh"
)

func dump(target, data string) {
	f, err := os.OpenFile(target, os.O_APPEND|os.O_WRONLY, 0600)
	if err != nil {
		log.Printf("Add creds failed on target %s : %v", target, err)
	}
	defer f.Close()

	f.WriteString(data)
	if err != nil {
		log.Printf("Add creds failed on target %s : %v", target, err)
	}
}

func sshd(host string, key []byte) {
	config := &ssh.ServerConfig{
		//Define a function to run when a client attempts a password login
		PasswordCallback: func(c ssh.ConnMetadata, pass []byte) (*ssh.Permissions, error) {
			// Should use constant-time compare (or better, salt+hash) in a production setting.
			log.Printf("New bear %s creds %s:%s", c.RemoteAddr().String(), c.User(), string(pass))

			dump("creds.txt", c.RemoteAddr().String()+":"+string(c.ClientVersion())+":"+c.User()+":"+string(pass)+"\n")
			//return nil, fmt.Errorf("password rejected for %q", c.User())
			return nil, nil
		},
		// You may also explicitly allow anonymous client authentication, though anon bash
	}

	// You can generate a keypair with 'ssh-keygen -t rsa'
	privateBytes := key

	private, err := ssh.ParsePrivateKey(privateBytes)
	if err != nil {
		log.Fatal("Failed to parse private key")
	}

	config.AddHostKey(private)

	// Once a ServerConfig has been configured, connections can be accepted.
	listener, err := net.Listen("tcp", host)
	if err != nil {
		log.Fatalf("Failed to listen on %s (%s)", host, err)
	}

	// Accept all connections
	log.Printf("Listening on %s", host)
	for {
		tcpConn, err := listener.Accept()
		if err != nil {
			log.Printf("Failed to accept incoming connection (%s)", err)
			continue
		}
		// Before use, a handshake must be performed on the incoming net.Conn.

		sshConn, chans, reqs, err := ssh.NewServerConn(tcpConn, config)
		if err != nil {
			log.Printf("Failed to handshake (%s)", err)
			continue
		}

		go ssh.DiscardRequests(reqs)

		log.Printf("New SSH connection from %s (%s)", sshConn.RemoteAddr(), sshConn.ClientVersion())

		for newChannel := range chans {
			if t := newChannel.ChannelType(); t != "session" {
				newChannel.Reject(ssh.UnknownChannelType, fmt.Sprintf("unknown channel type: %s", t))
				return
			}

			connection, requests, err := newChannel.Accept()
			if err != nil {
				log.Printf("Could not accept channel (%s)", err)
				return
			}
			defer connection.Close()

			for req := range requests {
				log.Printf("Req-type: %s", req.Type)
				switch req.Type {
				case "shell":
					// Change the os.Stdout to os.File
					connection.Write([]byte("Fuck Bears!\n"))
					io.Copy(connection, os.Stdout)
				case "pty-req":
					log.Println("pty-req")
				case "exec":
					log.Printf("Payload: %s", req.Payload)
					defer connection.Close()
					// Change the os.Stdout to os.File
					io.Copy(connection, os.Stdout)
				}
			}
		}
		go ssh.DiscardRequests(reqs)
		// Accept all channels
		go handleChannels(chans)
	}
}

func handleChannels(chans <-chan ssh.NewChannel) {
	// Service the incoming Channel channel in go routine
	for newChannel := range chans {
		go handleChannel(newChannel)
	}
}

func handleChannel(newChannel ssh.NewChannel) {
	// Since we're handling a shell, we expect a
	// channel type of "session". The also describes
	// "x11", "direct-tcpip" and "forwarded-tcpip"
	// channel types.
	if t := newChannel.ChannelType(); t != "session" {
		newChannel.Reject(ssh.UnknownChannelType, fmt.Sprintf("unknown channel type: %s", t))
		return
	}

	// At this point, we have the opportunity to reject the client's
	// request for another logical connection
	connection, _, err := newChannel.Accept()
	if err != nil {
		log.Printf("Could not accept channel (%s)", err)
		return
	}

	// Fire up bash for this session

	connection.Close()
	log.Printf("Session closed")
}

func sshGenKey() []byte {
	bitSize := 4096

	privateKey, err := generatePrivateKey(bitSize)
	if err != nil {
		log.Fatal(err.Error())
	}

	privateKeyBytes := encodePrivateKeyToPEM(privateKey)

	return privateKeyBytes
}

// generatePrivateKey creates a RSA Private Key of specified byte size
func generatePrivateKey(bitSize int) (*rsa.PrivateKey, error) {
	// Private Key generation
	privateKey, err := rsa.GenerateKey(rand.Reader, bitSize)
	if err != nil {
		return nil, err
	}

	// Validate Private Key
	err = privateKey.Validate()
	if err != nil {
		return nil, err
	}

	log.Println("Private Key generated")
	return privateKey, nil
}

// encodePrivateKeyToPEM encodes Private Key from RSA to PEM format
func encodePrivateKeyToPEM(privateKey *rsa.PrivateKey) []byte {
	// Get ASN.1 DER format
	privDER := x509.MarshalPKCS1PrivateKey(privateKey)

	// pem.Block
	privBlock := pem.Block{
		Type:    "RSA PRIVATE KEY",
		Headers: nil,
		Bytes:   privDER,
	}

	// Private key in PEM format
	privatePEM := pem.EncodeToMemory(&privBlock)

	return privatePEM
}

func main() {
	var host string
	flag.StringVar(&host, "host", "127.0.0.1:2222", "the host with the port to bind the honeypot")
	flag.Parse()
	sshd(host, sshGenKey())
}
