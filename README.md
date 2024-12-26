# PKI Communication Demo

This repository demonstrates a Public Key Infrastructure (PKI) communication system implemented using microservices architecture and gRPC communication. The system consists of three services: Party A, Party B, and the Certificate Authority (CA). 

## Overview

- **Certificate Authority (CA)**: Issues certificates and provides its public key to clients for certificate verification.
- **Party A**: Requests Party B's certificate, verifies it, and sends messages to Party B.
- **Party B**: Receives messages from Party A, verifies the certificate, and decrypts the messages using a session key.

## Workflow

1. **Certificate Request**: 
   - Party A calls the `SendCertificate` method of Party B to obtain its certificate.
   - Party A verifies Party B's certificate by comparing the signature with the hash of Party B's information.

2. **Message Sending**:
   - After successful verification, Party A calls Party B's `ReceiveMessage` method to send a message.

3. **Certificate Verification**:
   - Party B verifies the received certificate. If successful, it retrieves the session key from the message data.

4. **Message Decryption**:
   - Using the session key and nonce from the message, Party B decrypts the encrypted message and logs it to the console.

## Getting Started

### Prerequisites

- Go 1.22.5 or later
- gRPC and Protocol Buffers

### Installation

1. Clone the repository:
   ```bash
   git clone https://github.com/yishak-cs/New-PKIcls.git
   cd New-PKIcls
   ```

2. Install dependencies:
   ```bash
   go mod tidy
   ```

### Running the Services

1. Start the Certificate Authority (CA):
   ```bash
   go run CA/main.go
   ```

2. Start Party B in a new terminal:
   ```bash
   go run B/main.go
   ```

3. Start Party A in another terminal:
   ```bash
   go run A/main.go
   ```

### Usage

- Once all services are running, Party A will automatically request Party B's certificate, verify it, and send a message.
- Party B will log the received message to the console after decrypting it.
