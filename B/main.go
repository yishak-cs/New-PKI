package main

import (
	"bytes"
	"context"
	"crypto"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"log"
	"math/big"
	"net"

	pb "github.com/yishak-cs/New-PKIcls/protogen"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/status"
)

type PartyBServices struct {
	SessionKey []byte
	pb.UnimplementedPartyBServiceServer
}

var numberOnce string

// party B private and public keys
var bPrivateKey, _ = rsa.GenerateKey(rand.Reader, 2048)
var bPublicKey = &bPrivateKey.PublicKey

func (a *PartyBServices) SendCertificate(ctx context.Context, empty *pb.Empty) (*pb.CertficateResponse, error) {
	// cryptocratic number generation for the serialNumber of the Cert
	max := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, _ := rand.Int(rand.Reader, max)

	select {
	case <-ctx.Done():
		return nil, status.Errorf(codes.Canceled, "request canceled")
	default:
	}

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

	return Cert, nil
}

func (b *PartyBServices) ReceiveMessage(ctx context.Context, d *pb.Data) (*pb.Empty, error) {

	if b.SessionKey == nil && d.GetSubsequentMessage() != nil {
		return nil, fmt.Errorf("session key has not been established")
	}

	switch data := d.Payload.(type) {

	case *pb.Data_InitialMessage:
		if _, err := b.VerifyCertificate(ctx, data.InitialMessage.SenderCertificate); err != nil {
			return nil, fmt.Errorf("something went wrong")
		}
		log.Println("A's Certificate verified successfully")
		eSessionKey, prob := base64.StdEncoding.DecodeString(data.InitialMessage.EncryptedSessionKey)
		if prob != nil {
			return nil, fmt.Errorf("%v", prob)
		}

		var err error
		b.SessionKey, err = rsa.DecryptPKCS1v15(rand.Reader, bPrivateKey, eSessionKey)

		if err != nil {
			return nil, fmt.Errorf("failed to decrypt the session key: %v", err)
		}
		log.Printf("\t The Session Key:\n %v \n \t#######", string(b.SessionKey))

		eMessage, prob := base64.StdEncoding.DecodeString(data.InitialMessage.EncryptedMessage)
		if prob != nil {
			return nil, fmt.Errorf("%v", prob)
		}

		numberOnce = data.InitialMessage.Nonce

		message, err := b.decryptMessage(eMessage, numberOnce)

		if err != nil {
			return nil, fmt.Errorf("failed to decrypt message: %v", err)
		}

		fmt.Printf("\t Party A said: \t %s", string(message))

		return &pb.Empty{}, nil

	case *pb.Data_SubsequentMessage:
		// Decrypt message using stored session key
		message, err := b.decryptMessage([]byte(data.SubsequentMessage.EncryptedMessage), numberOnce)

		if err != nil {
			return nil, fmt.Errorf("failed to decrypt message: %v", err)
		}

		fmt.Printf("\tParty A said: \t %s", string(message))
		return &pb.Empty{}, nil

	}
	return nil, fmt.Errorf("something went wrong")
}

func (b *PartyBServices) decryptMessage(ciphertext []byte, numOnce string) ([]byte, error) {
	block, err := aes.NewCipher(b.SessionKey)
	if err != nil {
		return nil, fmt.Errorf("failed to create cipher: %v", err)
	}
	gcm, err := cipher.NewGCM(block)

	if err != nil {
		return nil, fmt.Errorf("failed to create GCM: %v", err)
	}
	nonce, _ := hex.DecodeString(numOnce)

	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)

	if err != nil {
		return nil, fmt.Errorf("failed to decrypt: %v", err)
	}
	return plaintext, nil
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

	// hash the CSR data of party A
	var buffer bytes.Buffer
	buffer.WriteString(resp.SubjectName)
	buffer.Write(resp.CertSerialNumber)
	buffer.WriteString(resp.PubKey)
	hash := sha256.Sum256(buffer.Bytes())

	caSign, _ := base64.StdEncoding.DecodeString(resp.Signature)

	problem := rsa.VerifyPKCS1v15(key, crypto.SHA256, hash[:], caSign)

	if problem != nil {
		return nil, fmt.Errorf("failed to verify certificate: %v", problem)
	}
	return &pb.Empty{}, nil
}

func main() {

	conn, err := net.Listen("tcp", "localhost:50050")

	if err != nil {
		log.Fatalf("failed to listen on %v: %v", conn, err)
	}

	server := grpc.NewServer()
	pb.RegisterPartyBServiceServer(server, &PartyBServices{})

	log.Println("B's Service is running on port 50050...")
	if err := server.Serve(conn); err != nil {
		log.Fatalf("Failed to serve: %v", err)
	}

}
