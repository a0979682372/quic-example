package main

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"math/big"
	"time"

	"github.com/quic-go/quic-go"
)

func main() {
	fmt.Println("hello")
	err := Server()
	if err != nil {
		fmt.Println("server err")
		fmt.Println(err)
	}

}

func Server() error {
	const addr = "10.0.2.15:30000"
	ctx, cancel := context.WithTimeout(context.Background(), time.Hour)
	defer cancel()

	listener, err := quic.ListenAddr(addr, generateTLSConfig(), &quic.Config{
		KeepAlivePeriod: time.Minute * 5,
		EnableDatagrams: true,
	})
	if err != nil {
		return err
	}

	conn, err := listener.Accept(ctx)
	if err != nil {
		return err
	}

	for {
		size := 256
		buf := make([]byte, size)
		buf, err = conn.ReceiveMessage()
		if err != nil {
			fmt.Println(err)
			break
		}
		fmt.Printf("Got: %s", buf)

	}
	return err

}

// Setup a bare-bones TLS config for the server
func generateTLSConfig() *tls.Config {
	key, err := rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		panic(err)
	}
	template := x509.Certificate{SerialNumber: big.NewInt(1)}
	certDER, err := x509.CreateCertificate(rand.Reader, &template, &template, &key.PublicKey, key)
	if err != nil {
		panic(err)
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})

	tlsCert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		panic(err)
	}
	return &tls.Config{
		Certificates: []tls.Certificate{tlsCert},
		NextProtos:   []string{"quic-echo-example"},
	}
}
