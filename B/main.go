package main

import (
	"bytes"
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"log"
	"math/big"
	"net"
	"time"

	pb "github.com/yishak-cs/New-PKIcls/protogen"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

type PartyBServices struct {
	pb.UnimplementedPartyAServiceServer
}

// party B private and public keys
var bPrivateKey, _ = rsa.GenerateKey(rand.Reader, 2048)
var bPublicKey = &bPrivateKey.PublicKey

func (a *PartyBServices) SendCertificate(ctx context.Context, empty *pb.Empty) (*pb.CertficateResponse, error) {
	// cryptocratic number generation for the serialNumber of the Cert
	max := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, _ := rand.Int(rand.Reader, max)

	// covert the B's public key to []byte
	publicKeyDER := x509.MarshalPKCS1PublicKey(bPublicKey)

	// Encode the public key to as a PEM block in memory as opposed to a file
	publicKeyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PUBLIC KEY",
		Bytes: publicKeyDER,
	})

	//prepare a certificate request
	request := pb.CertificateRequest{
		CommonName:   "Party B",
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

func (a *PartyBServices) VerifyCertificate(ctx context.Context, resp *pb.CertficateResponse) (*pb.Empty, error) {

	// connect with the CA service to obtain CA public key
	// used for letter checking if the signed hash of A's info matches with
	// what the CA guarentees A's info is (signature of A's Certificate)
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

	// PEM(privacy enhance email) block
	CApubkeyBlock, _ := pem.Decode([]byte(CApubkey.PublicKey))

	if CApubkeyBlock == nil {
		return nil, fmt.Errorf("failed to decode CA's public key")
	}
	// extract the public key of CA
	key, err := x509.ParsePKCS1PublicKey(CApubkeyBlock.Bytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse CA's public key: %v", err)
	}

	// hash the CSR data of party A
	var buffer bytes.Buffer
	buffer.WriteString(resp.SubjectName)
	buffer.Write(resp.CertSerialNumber)
	buffer.WriteString(resp.PubKey)
	hash := sha256.Sum256(buffer.Bytes())

	problem := rsa.VerifyPKCS1v15(key, crypto.SHA256, hash[:], []byte(resp.Signature))

	if problem != nil {
		return nil, fmt.Errorf("failed to verify certificate: %v", problem)
	}
	return &pb.Empty{}, nil
}

func main() {

	go func() {
		// get new grpc client to connect with A
		aClient, err := grpc.NewClient("localhost:50000", grpc.WithTransportCredentials(insecure.NewCredentials()))

		if err != nil {
			log.Fatal(err)
		}
		defer aClient.Close()
		// use the grpc client to connect with A's server and obtain A's service client
		client := pb.NewPartyAServiceClient(aClient)

		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		// use A's client(stub) to invoke SendCertificate method
		cert, err := client.SendCertificate(ctx, &pb.Empty{})
		if err != nil {
			log.Fatal(err)
		}

		//create an instance of party A
		b := PartyBServices{}

		_, prob := b.VerifyCertificate(ctx, cert)

		if prob != nil {
			log.Fatalf("failed to verify public key: %v", prob)
		}
		// verification is successful
		log.Println("Public key verified successfully")
		// process the message sent
		//
		//
	}()

	conn, err := net.Listen("tcp", "localhost:50000")

	if err != nil {
		log.Fatalf("failed to listen on %v: %v", conn, err)
	}

	server := grpc.NewServer()
	pb.RegisterPartyAServiceServer(server, &PartyBServices{})

	log.Println("B's Service is running on port 50000...")
	if err := server.Serve(conn); err != nil {
		log.Fatalf("Failed to serve: %v", err)
	}
}
