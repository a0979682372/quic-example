package main

import (
	"bufio"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"math/big"
	"os"
	"time"

	"github.com/quic-go/quic-go"
)

const addr = "10.0.2.15:30000"

func main() {
	fmt.Println("hello")
	err := Client()
	if err != nil {
		fmt.Println("client err")
		fmt.Println(err)
	}

}

func Client() error {
	tlsConf := &tls.Config{
		InsecureSkipVerify: true,
		NextProtos:         []string{"quic-echo-example"},
	}
	conn, err := quic.DialAddr(addr, tlsConf, &quic.Config{
		KeepAlivePeriod: time.Minute * 5,
		EnableDatagrams: true,
	})
	if err != nil {
		fmt.Println("conn err")
		return err
	}
	reader := bufio.NewReader(os.Stdin)
	for {
		fmt.Println("What message do you want to send?")
		fmt.Print("message: ")
		text, _ := reader.ReadString('\n')
		sendData := []byte(text)
		err = conn.SendMessage(sendData)
		if err != nil {
			fmt.Println(err)
			return err
		}
		time.Sleep(1 * time.Second)
	}
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
