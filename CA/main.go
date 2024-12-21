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
	"net"

	pb "github.com/yishak-cs/New-PKIcls/protogen"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

type CAuthority struct {
	pb.UnimplementedCAServiceServer
}

var privateKey, _ = rsa.GenerateKey(rand.Reader, 2048)
var publicKey = &privateKey.PublicKey

func validateRequest(req *pb.CertificateRequest) error {
	if req.CommonName == "" {
		return fmt.Errorf("common name is required")
	}
	if req.SerialNumber == nil {
		return fmt.Errorf("serial number is required")
	}
	if req.PublicKey == "" {
		return fmt.Errorf("what do you want me to sign dumbass!!? Public Key is required")
	}
	return nil
}

func (ca *CAuthority) IssueCertificate(ctx context.Context, req *pb.CertificateRequest) (*pb.CertficateResponse, error) {

	if err := validateRequest(req); err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "invalid request: %v", err)
	}

	select {
	case <-ctx.Done():
		return nil, status.Errorf(codes.Canceled, "request canceled")
	default:
	}

	//put all the data into a single byte to perpare it for hashing
	var buffer bytes.Buffer
	buffer.WriteString(req.CommonName)
	buffer.Write(req.SerialNumber)
	buffer.WriteString(req.PublicKey)

	hash := sha256.Sum256(buffer.Bytes())

	// CA signing hash of clients data using its private key.
	signature, err := rsa.SignPKCS1v15(rand.Reader, privateKey, crypto.SHA256, hash[:])

	if err != nil {
		return nil, fmt.Errorf("failed to sign %s 's certificate: %v", req.CommonName, err)
	}

	// base 64 encoding of the signature
	signatureBase64 := base64.StdEncoding.EncodeToString(signature)

	resp := pb.CertficateResponse{
		SubjectName:      req.CommonName,
		CertSerialNumber: req.SerialNumber,
		PubKey:           req.PublicKey,
		Issuer:           "CERTIFICATE AUTHORITY b**ch",
		Signature:        signatureBase64,
	}

	return &resp, nil
}

func (ca *CAuthority) GetPublicKey(ctx context.Context, empty *pb.Empty) (*pb.CAPublicKey, error) {
	// marshal the public key into []byte
	publicKeyByte := x509.MarshalPKCS1PublicKey(publicKey)
	// store it in memory
	pub := pem.EncodeToMemory(&pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: publicKeyByte,
	})

	return &pb.CAPublicKey{PublicKey: base64.StdEncoding.EncodeToString(pub)}, nil
}

func main() {
	address := "localhost:50500"

	conn, err := net.Listen("tcp", address)
	if err != nil {
		log.Fatal("failed to listen")
	}

	server := grpc.NewServer()
	pb.RegisterCAServiceServer(server, &CAuthority{})

	log.Println("server is now running on [port 50500]")
	if err := server.Serve(conn); err != nil {
		log.Fatalf("server failed to start: %v", err)
	}
}
