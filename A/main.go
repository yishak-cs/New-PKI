package main

import (
	"bytes"
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"log"
	"math/big"
	"net"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"

	pb "github.com/yishak-cs/New-PKIcls/protogen"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/status"
)

type PartyAServices struct {
	pb.UnimplementedPartyAServiceServer
}

// party A private and public keys
var aPrivateKey, _ = rsa.GenerateKey(rand.Reader, 2048)
var aPublicKey = &aPrivateKey.PublicKey

func (a *PartyAServices) SendCertificate(ctx context.Context, empty *pb.Empty) (*pb.CertficateResponse, error) {
	// cryptocratic number generation for the serialNumber of the Cert
	max := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, _ := rand.Int(rand.Reader, max)

	select {
	case <-ctx.Done():
		return nil, status.Errorf(codes.Canceled, "request canceled")
	default:
	}

	// seriallize the A's public key to []byte
	publicKeyDER := x509.MarshalPKCS1PublicKey(aPublicKey)

	// Encode the public key to as a PEM block in memory as opposed to a file
	publicKeyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PUBLIC KEY",
		Bytes: publicKeyDER,
	})

	//prepare a certificate request
	request := pb.CertificateRequest{
		CommonName:   "Party A",
		SerialNumber: []byte(serialNumber.String()),
		PublicKey:    string(publicKeyPEM),
	}

	// connect with the CA
	caClient, err := grpc.NewClient("localhost:50500", grpc.WithTransportCredentials(insecure.NewCredentials()))

	if err != nil {
		return nil, fmt.Errorf("failed to connect with CA: %v", err)
	}
	// defer the connection close to the end of function execution
	defer caClient.Close()

	// get new CA service client
	client := pb.NewCAServiceClient(caClient)

	// invoke issue sertificate method of CAService
	Cert, err := client.IssueCertificate(context.Background(), &request)
	if err != nil {
		return nil, fmt.Errorf("failed to obtain certificate: %v", err)
	}

	log.Println(Cert.Signature)
	return Cert, nil
}

func (a *PartyAServices) SendMessage(ctx context.Context, d *pb.Data) (*pb.Empty, error) {
	return nil, nil
	//
	//
	//
}

func (a *PartyAServices) VerifyCertificate(ctx context.Context, resp *pb.CertficateResponse) (*pb.Empty, error) {

	// connect with the CA service to obtain CA public key
	// used for letter checking if the signed hash of B's info matches with
	// what the CA guarentees B's info is (signature of B's Certificate)
	caClient, err := grpc.NewClient("localhost:50500", grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		return nil, fmt.Errorf("failed to connect to CA: %v", err)
	}

	//defer connection close
	defer caClient.Close()

	client := pb.NewCAServiceClient(caClient)

	// invoke GetPublicKey method of CA service
	CApubkey, err := client.GetPublicKey(ctx, &pb.Empty{})
	if err != nil {
		return nil, fmt.Errorf("failed to get CA's public key: %v", err)
	}

	// First decode the base64 string
	pemBytes, err := base64.StdEncoding.DecodeString(CApubkey.PublicKey)
	if err != nil {
		return nil, fmt.Errorf("failed to decode base64 public key: %v", err)
	}

	// Then decode the PEM
	CApubkeyBlock, _ := pem.Decode(pemBytes)

	if CApubkeyBlock == nil {
		return nil, fmt.Errorf("failed to decode CA's public key")
	}
	// extract the public key of CA
	key, err := x509.ParsePKCS1PublicKey(CApubkeyBlock.Bytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse CA's public key: %v", err)
	}

	// hash the CSR data of party B
	var buffer bytes.Buffer
	buffer.WriteString(resp.SubjectName)
	buffer.Write(resp.CertSerialNumber)
	buffer.WriteString(resp.PubKey)
	hash := sha256.Sum256(buffer.Bytes())

	caSign, err := base64.StdEncoding.DecodeString(resp.Signature)
	if err != nil {
		return nil, fmt.Errorf("failed to verify certificate: %v", err)
	}
	problem := rsa.VerifyPKCS1v15(key, crypto.SHA256, hash[:], caSign)

	if problem != nil {
		return nil, fmt.Errorf("failed to verify certificate: %v", problem)
	}
	return &pb.Empty{}, nil
}

func main() {
	// wait groun so the main routine doesnt exit before
	// routines it created exit.
	var wg sync.WaitGroup

	wg.Add(1)

	// Create channel for shutdown signals
	shutdown := make(chan os.Signal, 1)
	signal.Notify(shutdown, syscall.SIGINT, syscall.SIGTERM)

	//channel for errors
	errors := make(chan error)

	//create a grpc server
	server := grpc.NewServer()

	go func() {
		defer wg.Done()

		for retries := 0; retries < 3; retries++ {
			// get new grpc client to connect with B
			aClient, err := grpc.NewClient("localhost:50000", grpc.WithTransportCredentials(insecure.NewCredentials()))

			if err != nil {
				log.Printf("Attempt %d: Failed to connect to Party A: %v", retries+1, err)
				time.Sleep(2 * time.Second)
				continue
			}
			defer aClient.Close()
			// use the grpc client to connect with B's server and obtain B's service client
			client := pb.NewPartyAServiceClient(aClient)

			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			// use B's client(stub) to invoke SendCertificate method
			cert, err := client.SendCertificate(ctx, &pb.Empty{})
			if err != nil {
				log.Printf("Failed to get certificate: %v", err)
				continue
			}

			//create an instance of party A
			b := PartyAServices{}

			_, prob := b.VerifyCertificate(ctx, cert)

			if prob != nil {
				errors <- fmt.Errorf("failed to verify public key: %v", prob)
				return
			}
			// verification is successful
			log.Println("Public key verified successfully")
			// process the message sent
			//
			//
			return
		}
		errors <- fmt.Errorf("failed to establish connection after 3 retries")
	}()

	go func() {
		conn, err := net.Listen("tcp", "localhost:50050")

		if err != nil {
			errors <- fmt.Errorf("failed to listen: %v", err)
			return
		}

		server := grpc.NewServer()
		pb.RegisterPartyAServiceServer(server, &PartyAServices{})

		log.Println("B's Service is running on port 50000...")
		if err := server.Serve(conn); err != nil {
			errors <- fmt.Errorf("failed to serve: %v", err)
			return
		}
	}()
	select {
	case <-shutdown:
		log.Println("shutting down gracefully")
		server.GracefulStop()
	case err := <-errors:
		log.Printf("error occured: %v", err)
		server.Stop()
	}
	wg.Wait()
}
