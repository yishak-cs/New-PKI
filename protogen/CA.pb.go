// Code generated by protoc-gen-go. DO NOT EDIT.
// versions:
// 	protoc-gen-go v1.36.0
// 	protoc        v5.28.1
// source: CA.proto

package protogen

import (
	protoreflect "google.golang.org/protobuf/reflect/protoreflect"
	protoimpl "google.golang.org/protobuf/runtime/protoimpl"
	reflect "reflect"
	sync "sync"
)

const (
	// Verify that this generated code is sufficiently up-to-date.
	_ = protoimpl.EnforceVersion(20 - protoimpl.MinVersion)
	// Verify that runtime/protoimpl is sufficiently up-to-date.
	_ = protoimpl.EnforceVersion(protoimpl.MaxVersion - 20)
)

type CertificateRequest struct {
	state         protoimpl.MessageState `protogen:"open.v1"`
	CommonName    string                 `protobuf:"bytes,1,opt,name=common_name,json=commonName,proto3" json:"common_name,omitempty"`
	SerialNumber  []byte                 `protobuf:"bytes,2,opt,name=serial_number,json=serialNumber,proto3" json:"serial_number,omitempty"`
	PublicKey     string                 `protobuf:"bytes,3,opt,name=public_key,json=publicKey,proto3" json:"public_key,omitempty"`
	unknownFields protoimpl.UnknownFields
	sizeCache     protoimpl.SizeCache
}

func (x *CertificateRequest) Reset() {
	*x = CertificateRequest{}
	mi := &file_CA_proto_msgTypes[0]
	ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
	ms.StoreMessageInfo(mi)
}

func (x *CertificateRequest) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*CertificateRequest) ProtoMessage() {}

func (x *CertificateRequest) ProtoReflect() protoreflect.Message {
	mi := &file_CA_proto_msgTypes[0]
	if x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use CertificateRequest.ProtoReflect.Descriptor instead.
func (*CertificateRequest) Descriptor() ([]byte, []int) {
	return file_CA_proto_rawDescGZIP(), []int{0}
}

func (x *CertificateRequest) GetCommonName() string {
	if x != nil {
		return x.CommonName
	}
	return ""
}

func (x *CertificateRequest) GetSerialNumber() []byte {
	if x != nil {
		return x.SerialNumber
	}
	return nil
}

func (x *CertificateRequest) GetPublicKey() string {
	if x != nil {
		return x.PublicKey
	}
	return ""
}

type CertficateResponse struct {
	state            protoimpl.MessageState `protogen:"open.v1"`
	SubjectName      string                 `protobuf:"bytes,4,opt,name=subject_name,json=subjectName,proto3" json:"subject_name,omitempty"`
	CertSerialNumber []byte                 `protobuf:"bytes,5,opt,name=cert_serial_number,json=certSerialNumber,proto3" json:"cert_serial_number,omitempty"`
	PubKey           string                 `protobuf:"bytes,6,opt,name=pub_key,json=pubKey,proto3" json:"pub_key,omitempty"`
	Issuer           string                 `protobuf:"bytes,7,opt,name=issuer,proto3" json:"issuer,omitempty"`
	Signature        string                 `protobuf:"bytes,8,opt,name=signature,proto3" json:"signature,omitempty"`
	unknownFields    protoimpl.UnknownFields
	sizeCache        protoimpl.SizeCache
}

func (x *CertficateResponse) Reset() {
	*x = CertficateResponse{}
	mi := &file_CA_proto_msgTypes[1]
	ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
	ms.StoreMessageInfo(mi)
}

func (x *CertficateResponse) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*CertficateResponse) ProtoMessage() {}

func (x *CertficateResponse) ProtoReflect() protoreflect.Message {
	mi := &file_CA_proto_msgTypes[1]
	if x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use CertficateResponse.ProtoReflect.Descriptor instead.
func (*CertficateResponse) Descriptor() ([]byte, []int) {
	return file_CA_proto_rawDescGZIP(), []int{1}
}

func (x *CertficateResponse) GetSubjectName() string {
	if x != nil {
		return x.SubjectName
	}
	return ""
}

func (x *CertficateResponse) GetCertSerialNumber() []byte {
	if x != nil {
		return x.CertSerialNumber
	}
	return nil
}

func (x *CertficateResponse) GetPubKey() string {
	if x != nil {
		return x.PubKey
	}
	return ""
}

func (x *CertficateResponse) GetIssuer() string {
	if x != nil {
		return x.Issuer
	}
	return ""
}

func (x *CertficateResponse) GetSignature() string {
	if x != nil {
		return x.Signature
	}
	return ""
}

type CAPublicKey struct {
	state         protoimpl.MessageState `protogen:"open.v1"`
	PublicKey     string                 `protobuf:"bytes,9,opt,name=public_key,json=publicKey,proto3" json:"public_key,omitempty"`
	unknownFields protoimpl.UnknownFields
	sizeCache     protoimpl.SizeCache
}

func (x *CAPublicKey) Reset() {
	*x = CAPublicKey{}
	mi := &file_CA_proto_msgTypes[2]
	ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
	ms.StoreMessageInfo(mi)
}

func (x *CAPublicKey) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*CAPublicKey) ProtoMessage() {}

func (x *CAPublicKey) ProtoReflect() protoreflect.Message {
	mi := &file_CA_proto_msgTypes[2]
	if x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use CAPublicKey.ProtoReflect.Descriptor instead.
func (*CAPublicKey) Descriptor() ([]byte, []int) {
	return file_CA_proto_rawDescGZIP(), []int{2}
}

func (x *CAPublicKey) GetPublicKey() string {
	if x != nil {
		return x.PublicKey
	}
	return ""
}

type Empty struct {
	state         protoimpl.MessageState `protogen:"open.v1"`
	unknownFields protoimpl.UnknownFields
	sizeCache     protoimpl.SizeCache
}

func (x *Empty) Reset() {
	*x = Empty{}
	mi := &file_CA_proto_msgTypes[3]
	ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
	ms.StoreMessageInfo(mi)
}

func (x *Empty) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*Empty) ProtoMessage() {}

func (x *Empty) ProtoReflect() protoreflect.Message {
	mi := &file_CA_proto_msgTypes[3]
	if x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use Empty.ProtoReflect.Descriptor instead.
func (*Empty) Descriptor() ([]byte, []int) {
	return file_CA_proto_rawDescGZIP(), []int{3}
}

type InitialMessage struct {
	state               protoimpl.MessageState `protogen:"open.v1"`
	EncryptedSessionKey string                 `protobuf:"bytes,10,opt,name=encrypted_session_key,json=encryptedSessionKey,proto3" json:"encrypted_session_key,omitempty"`
	EncryptedMessage    string                 `protobuf:"bytes,11,opt,name=encrypted_message,json=encryptedMessage,proto3" json:"encrypted_message,omitempty"`
	SenderCertificate   *CertficateResponse    `protobuf:"bytes,12,opt,name=sender_certificate,json=senderCertificate,proto3" json:"sender_certificate,omitempty"`
	Nonce               string                 `protobuf:"bytes,13,opt,name=nonce,proto3" json:"nonce,omitempty"`
	unknownFields       protoimpl.UnknownFields
	sizeCache           protoimpl.SizeCache
}

func (x *InitialMessage) Reset() {
	*x = InitialMessage{}
	mi := &file_CA_proto_msgTypes[4]
	ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
	ms.StoreMessageInfo(mi)
}

func (x *InitialMessage) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*InitialMessage) ProtoMessage() {}

func (x *InitialMessage) ProtoReflect() protoreflect.Message {
	mi := &file_CA_proto_msgTypes[4]
	if x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use InitialMessage.ProtoReflect.Descriptor instead.
func (*InitialMessage) Descriptor() ([]byte, []int) {
	return file_CA_proto_rawDescGZIP(), []int{4}
}

func (x *InitialMessage) GetEncryptedSessionKey() string {
	if x != nil {
		return x.EncryptedSessionKey
	}
	return ""
}

func (x *InitialMessage) GetEncryptedMessage() string {
	if x != nil {
		return x.EncryptedMessage
	}
	return ""
}

func (x *InitialMessage) GetSenderCertificate() *CertficateResponse {
	if x != nil {
		return x.SenderCertificate
	}
	return nil
}

func (x *InitialMessage) GetNonce() string {
	if x != nil {
		return x.Nonce
	}
	return ""
}

type SubsequentMessage struct {
	state            protoimpl.MessageState `protogen:"open.v1"`
	EncryptedMessage string                 `protobuf:"bytes,14,opt,name=encrypted_message,json=encryptedMessage,proto3" json:"encrypted_message,omitempty"`
	unknownFields    protoimpl.UnknownFields
	sizeCache        protoimpl.SizeCache
}

func (x *SubsequentMessage) Reset() {
	*x = SubsequentMessage{}
	mi := &file_CA_proto_msgTypes[5]
	ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
	ms.StoreMessageInfo(mi)
}

func (x *SubsequentMessage) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*SubsequentMessage) ProtoMessage() {}

func (x *SubsequentMessage) ProtoReflect() protoreflect.Message {
	mi := &file_CA_proto_msgTypes[5]
	if x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use SubsequentMessage.ProtoReflect.Descriptor instead.
func (*SubsequentMessage) Descriptor() ([]byte, []int) {
	return file_CA_proto_rawDescGZIP(), []int{5}
}

func (x *SubsequentMessage) GetEncryptedMessage() string {
	if x != nil {
		return x.EncryptedMessage
	}
	return ""
}

type Data struct {
	state protoimpl.MessageState `protogen:"open.v1"`
	// Types that are valid to be assigned to Payload:
	//
	//	*Data_InitialMessage
	//	*Data_SubsequentMessage
	Payload       isData_Payload `protobuf_oneof:"payload"`
	unknownFields protoimpl.UnknownFields
	sizeCache     protoimpl.SizeCache
}

func (x *Data) Reset() {
	*x = Data{}
	mi := &file_CA_proto_msgTypes[6]
	ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
	ms.StoreMessageInfo(mi)
}

func (x *Data) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*Data) ProtoMessage() {}

func (x *Data) ProtoReflect() protoreflect.Message {
	mi := &file_CA_proto_msgTypes[6]
	if x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use Data.ProtoReflect.Descriptor instead.
func (*Data) Descriptor() ([]byte, []int) {
	return file_CA_proto_rawDescGZIP(), []int{6}
}

func (x *Data) GetPayload() isData_Payload {
	if x != nil {
		return x.Payload
	}
	return nil
}

func (x *Data) GetInitialMessage() *InitialMessage {
	if x != nil {
		if x, ok := x.Payload.(*Data_InitialMessage); ok {
			return x.InitialMessage
		}
	}
	return nil
}

func (x *Data) GetSubsequentMessage() *SubsequentMessage {
	if x != nil {
		if x, ok := x.Payload.(*Data_SubsequentMessage); ok {
			return x.SubsequentMessage
		}
	}
	return nil
}

type isData_Payload interface {
	isData_Payload()
}

type Data_InitialMessage struct {
	InitialMessage *InitialMessage `protobuf:"bytes,15,opt,name=initial_message,json=initialMessage,proto3,oneof"`
}

type Data_SubsequentMessage struct {
	SubsequentMessage *SubsequentMessage `protobuf:"bytes,16,opt,name=subsequent_message,json=subsequentMessage,proto3,oneof"`
}

func (*Data_InitialMessage) isData_Payload() {}

func (*Data_SubsequentMessage) isData_Payload() {}

var File_CA_proto protoreflect.FileDescriptor

var file_CA_proto_rawDesc = []byte{
	0x0a, 0x08, 0x43, 0x41, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x22, 0x79, 0x0a, 0x12, 0x43, 0x65,
	0x72, 0x74, 0x69, 0x66, 0x69, 0x63, 0x61, 0x74, 0x65, 0x52, 0x65, 0x71, 0x75, 0x65, 0x73, 0x74,
	0x12, 0x1f, 0x0a, 0x0b, 0x63, 0x6f, 0x6d, 0x6d, 0x6f, 0x6e, 0x5f, 0x6e, 0x61, 0x6d, 0x65, 0x18,
	0x01, 0x20, 0x01, 0x28, 0x09, 0x52, 0x0a, 0x63, 0x6f, 0x6d, 0x6d, 0x6f, 0x6e, 0x4e, 0x61, 0x6d,
	0x65, 0x12, 0x23, 0x0a, 0x0d, 0x73, 0x65, 0x72, 0x69, 0x61, 0x6c, 0x5f, 0x6e, 0x75, 0x6d, 0x62,
	0x65, 0x72, 0x18, 0x02, 0x20, 0x01, 0x28, 0x0c, 0x52, 0x0c, 0x73, 0x65, 0x72, 0x69, 0x61, 0x6c,
	0x4e, 0x75, 0x6d, 0x62, 0x65, 0x72, 0x12, 0x1d, 0x0a, 0x0a, 0x70, 0x75, 0x62, 0x6c, 0x69, 0x63,
	0x5f, 0x6b, 0x65, 0x79, 0x18, 0x03, 0x20, 0x01, 0x28, 0x09, 0x52, 0x09, 0x70, 0x75, 0x62, 0x6c,
	0x69, 0x63, 0x4b, 0x65, 0x79, 0x22, 0xb4, 0x01, 0x0a, 0x12, 0x43, 0x65, 0x72, 0x74, 0x66, 0x69,
	0x63, 0x61, 0x74, 0x65, 0x52, 0x65, 0x73, 0x70, 0x6f, 0x6e, 0x73, 0x65, 0x12, 0x21, 0x0a, 0x0c,
	0x73, 0x75, 0x62, 0x6a, 0x65, 0x63, 0x74, 0x5f, 0x6e, 0x61, 0x6d, 0x65, 0x18, 0x04, 0x20, 0x01,
	0x28, 0x09, 0x52, 0x0b, 0x73, 0x75, 0x62, 0x6a, 0x65, 0x63, 0x74, 0x4e, 0x61, 0x6d, 0x65, 0x12,
	0x2c, 0x0a, 0x12, 0x63, 0x65, 0x72, 0x74, 0x5f, 0x73, 0x65, 0x72, 0x69, 0x61, 0x6c, 0x5f, 0x6e,
	0x75, 0x6d, 0x62, 0x65, 0x72, 0x18, 0x05, 0x20, 0x01, 0x28, 0x0c, 0x52, 0x10, 0x63, 0x65, 0x72,
	0x74, 0x53, 0x65, 0x72, 0x69, 0x61, 0x6c, 0x4e, 0x75, 0x6d, 0x62, 0x65, 0x72, 0x12, 0x17, 0x0a,
	0x07, 0x70, 0x75, 0x62, 0x5f, 0x6b, 0x65, 0x79, 0x18, 0x06, 0x20, 0x01, 0x28, 0x09, 0x52, 0x06,
	0x70, 0x75, 0x62, 0x4b, 0x65, 0x79, 0x12, 0x16, 0x0a, 0x06, 0x69, 0x73, 0x73, 0x75, 0x65, 0x72,
	0x18, 0x07, 0x20, 0x01, 0x28, 0x09, 0x52, 0x06, 0x69, 0x73, 0x73, 0x75, 0x65, 0x72, 0x12, 0x1c,
	0x0a, 0x09, 0x73, 0x69, 0x67, 0x6e, 0x61, 0x74, 0x75, 0x72, 0x65, 0x18, 0x08, 0x20, 0x01, 0x28,
	0x09, 0x52, 0x09, 0x73, 0x69, 0x67, 0x6e, 0x61, 0x74, 0x75, 0x72, 0x65, 0x22, 0x2c, 0x0a, 0x0b,
	0x43, 0x41, 0x50, 0x75, 0x62, 0x6c, 0x69, 0x63, 0x4b, 0x65, 0x79, 0x12, 0x1d, 0x0a, 0x0a, 0x70,
	0x75, 0x62, 0x6c, 0x69, 0x63, 0x5f, 0x6b, 0x65, 0x79, 0x18, 0x09, 0x20, 0x01, 0x28, 0x09, 0x52,
	0x09, 0x70, 0x75, 0x62, 0x6c, 0x69, 0x63, 0x4b, 0x65, 0x79, 0x22, 0x07, 0x0a, 0x05, 0x45, 0x6d,
	0x70, 0x74, 0x79, 0x22, 0xcb, 0x01, 0x0a, 0x0e, 0x49, 0x6e, 0x69, 0x74, 0x69, 0x61, 0x6c, 0x4d,
	0x65, 0x73, 0x73, 0x61, 0x67, 0x65, 0x12, 0x32, 0x0a, 0x15, 0x65, 0x6e, 0x63, 0x72, 0x79, 0x70,
	0x74, 0x65, 0x64, 0x5f, 0x73, 0x65, 0x73, 0x73, 0x69, 0x6f, 0x6e, 0x5f, 0x6b, 0x65, 0x79, 0x18,
	0x0a, 0x20, 0x01, 0x28, 0x09, 0x52, 0x13, 0x65, 0x6e, 0x63, 0x72, 0x79, 0x70, 0x74, 0x65, 0x64,
	0x53, 0x65, 0x73, 0x73, 0x69, 0x6f, 0x6e, 0x4b, 0x65, 0x79, 0x12, 0x2b, 0x0a, 0x11, 0x65, 0x6e,
	0x63, 0x72, 0x79, 0x70, 0x74, 0x65, 0x64, 0x5f, 0x6d, 0x65, 0x73, 0x73, 0x61, 0x67, 0x65, 0x18,
	0x0b, 0x20, 0x01, 0x28, 0x09, 0x52, 0x10, 0x65, 0x6e, 0x63, 0x72, 0x79, 0x70, 0x74, 0x65, 0x64,
	0x4d, 0x65, 0x73, 0x73, 0x61, 0x67, 0x65, 0x12, 0x42, 0x0a, 0x12, 0x73, 0x65, 0x6e, 0x64, 0x65,
	0x72, 0x5f, 0x63, 0x65, 0x72, 0x74, 0x69, 0x66, 0x69, 0x63, 0x61, 0x74, 0x65, 0x18, 0x0c, 0x20,
	0x01, 0x28, 0x0b, 0x32, 0x13, 0x2e, 0x43, 0x65, 0x72, 0x74, 0x66, 0x69, 0x63, 0x61, 0x74, 0x65,
	0x52, 0x65, 0x73, 0x70, 0x6f, 0x6e, 0x73, 0x65, 0x52, 0x11, 0x73, 0x65, 0x6e, 0x64, 0x65, 0x72,
	0x43, 0x65, 0x72, 0x74, 0x69, 0x66, 0x69, 0x63, 0x61, 0x74, 0x65, 0x12, 0x14, 0x0a, 0x05, 0x6e,
	0x6f, 0x6e, 0x63, 0x65, 0x18, 0x0d, 0x20, 0x01, 0x28, 0x09, 0x52, 0x05, 0x6e, 0x6f, 0x6e, 0x63,
	0x65, 0x22, 0x40, 0x0a, 0x11, 0x53, 0x75, 0x62, 0x73, 0x65, 0x71, 0x75, 0x65, 0x6e, 0x74, 0x4d,
	0x65, 0x73, 0x73, 0x61, 0x67, 0x65, 0x12, 0x2b, 0x0a, 0x11, 0x65, 0x6e, 0x63, 0x72, 0x79, 0x70,
	0x74, 0x65, 0x64, 0x5f, 0x6d, 0x65, 0x73, 0x73, 0x61, 0x67, 0x65, 0x18, 0x0e, 0x20, 0x01, 0x28,
	0x09, 0x52, 0x10, 0x65, 0x6e, 0x63, 0x72, 0x79, 0x70, 0x74, 0x65, 0x64, 0x4d, 0x65, 0x73, 0x73,
	0x61, 0x67, 0x65, 0x22, 0x92, 0x01, 0x0a, 0x04, 0x44, 0x61, 0x74, 0x61, 0x12, 0x3a, 0x0a, 0x0f,
	0x69, 0x6e, 0x69, 0x74, 0x69, 0x61, 0x6c, 0x5f, 0x6d, 0x65, 0x73, 0x73, 0x61, 0x67, 0x65, 0x18,
	0x0f, 0x20, 0x01, 0x28, 0x0b, 0x32, 0x0f, 0x2e, 0x49, 0x6e, 0x69, 0x74, 0x69, 0x61, 0x6c, 0x4d,
	0x65, 0x73, 0x73, 0x61, 0x67, 0x65, 0x48, 0x00, 0x52, 0x0e, 0x69, 0x6e, 0x69, 0x74, 0x69, 0x61,
	0x6c, 0x4d, 0x65, 0x73, 0x73, 0x61, 0x67, 0x65, 0x12, 0x43, 0x0a, 0x12, 0x73, 0x75, 0x62, 0x73,
	0x65, 0x71, 0x75, 0x65, 0x6e, 0x74, 0x5f, 0x6d, 0x65, 0x73, 0x73, 0x61, 0x67, 0x65, 0x18, 0x10,
	0x20, 0x01, 0x28, 0x0b, 0x32, 0x12, 0x2e, 0x53, 0x75, 0x62, 0x73, 0x65, 0x71, 0x75, 0x65, 0x6e,
	0x74, 0x4d, 0x65, 0x73, 0x73, 0x61, 0x67, 0x65, 0x48, 0x00, 0x52, 0x11, 0x73, 0x75, 0x62, 0x73,
	0x65, 0x71, 0x75, 0x65, 0x6e, 0x74, 0x4d, 0x65, 0x73, 0x73, 0x61, 0x67, 0x65, 0x42, 0x09, 0x0a,
	0x07, 0x70, 0x61, 0x79, 0x6c, 0x6f, 0x61, 0x64, 0x32, 0x6f, 0x0a, 0x09, 0x43, 0x41, 0x53, 0x65,
	0x72, 0x76, 0x69, 0x63, 0x65, 0x12, 0x3c, 0x0a, 0x10, 0x49, 0x73, 0x73, 0x75, 0x65, 0x43, 0x65,
	0x72, 0x74, 0x69, 0x66, 0x69, 0x63, 0x61, 0x74, 0x65, 0x12, 0x13, 0x2e, 0x43, 0x65, 0x72, 0x74,
	0x69, 0x66, 0x69, 0x63, 0x61, 0x74, 0x65, 0x52, 0x65, 0x71, 0x75, 0x65, 0x73, 0x74, 0x1a, 0x13,
	0x2e, 0x43, 0x65, 0x72, 0x74, 0x66, 0x69, 0x63, 0x61, 0x74, 0x65, 0x52, 0x65, 0x73, 0x70, 0x6f,
	0x6e, 0x73, 0x65, 0x12, 0x24, 0x0a, 0x0c, 0x47, 0x65, 0x74, 0x50, 0x75, 0x62, 0x6c, 0x69, 0x63,
	0x4b, 0x65, 0x79, 0x12, 0x06, 0x2e, 0x45, 0x6d, 0x70, 0x74, 0x79, 0x1a, 0x0c, 0x2e, 0x43, 0x41,
	0x50, 0x75, 0x62, 0x6c, 0x69, 0x63, 0x4b, 0x65, 0x79, 0x32, 0x92, 0x01, 0x0a, 0x0d, 0x50, 0x61,
	0x72, 0x74, 0x79, 0x41, 0x53, 0x65, 0x72, 0x76, 0x69, 0x63, 0x65, 0x12, 0x2e, 0x0a, 0x0f, 0x53,
	0x65, 0x6e, 0x64, 0x43, 0x65, 0x72, 0x74, 0x69, 0x66, 0x69, 0x63, 0x61, 0x74, 0x65, 0x12, 0x06,
	0x2e, 0x45, 0x6d, 0x70, 0x74, 0x79, 0x1a, 0x13, 0x2e, 0x43, 0x65, 0x72, 0x74, 0x66, 0x69, 0x63,
	0x61, 0x74, 0x65, 0x52, 0x65, 0x73, 0x70, 0x6f, 0x6e, 0x73, 0x65, 0x12, 0x30, 0x0a, 0x11, 0x76,
	0x65, 0x72, 0x69, 0x66, 0x79, 0x43, 0x65, 0x72, 0x74, 0x69, 0x66, 0x69, 0x63, 0x61, 0x74, 0x65,
	0x12, 0x13, 0x2e, 0x43, 0x65, 0x72, 0x74, 0x66, 0x69, 0x63, 0x61, 0x74, 0x65, 0x52, 0x65, 0x73,
	0x70, 0x6f, 0x6e, 0x73, 0x65, 0x1a, 0x06, 0x2e, 0x45, 0x6d, 0x70, 0x74, 0x79, 0x12, 0x1f, 0x0a,
	0x0e, 0x52, 0x65, 0x63, 0x65, 0x69, 0x76, 0x65, 0x4d, 0x65, 0x73, 0x73, 0x61, 0x67, 0x65, 0x12,
	0x05, 0x2e, 0x44, 0x61, 0x74, 0x61, 0x1a, 0x06, 0x2e, 0x45, 0x6d, 0x70, 0x74, 0x79, 0x32, 0x92,
	0x01, 0x0a, 0x0d, 0x50, 0x61, 0x72, 0x74, 0x79, 0x42, 0x53, 0x65, 0x72, 0x76, 0x69, 0x63, 0x65,
	0x12, 0x2e, 0x0a, 0x0f, 0x53, 0x65, 0x6e, 0x64, 0x43, 0x65, 0x72, 0x74, 0x69, 0x66, 0x69, 0x63,
	0x61, 0x74, 0x65, 0x12, 0x06, 0x2e, 0x45, 0x6d, 0x70, 0x74, 0x79, 0x1a, 0x13, 0x2e, 0x43, 0x65,
	0x72, 0x74, 0x66, 0x69, 0x63, 0x61, 0x74, 0x65, 0x52, 0x65, 0x73, 0x70, 0x6f, 0x6e, 0x73, 0x65,
	0x12, 0x30, 0x0a, 0x11, 0x76, 0x65, 0x72, 0x69, 0x66, 0x79, 0x43, 0x65, 0x72, 0x74, 0x69, 0x66,
	0x69, 0x63, 0x61, 0x74, 0x65, 0x12, 0x13, 0x2e, 0x43, 0x65, 0x72, 0x74, 0x66, 0x69, 0x63, 0x61,
	0x74, 0x65, 0x52, 0x65, 0x73, 0x70, 0x6f, 0x6e, 0x73, 0x65, 0x1a, 0x06, 0x2e, 0x45, 0x6d, 0x70,
	0x74, 0x79, 0x12, 0x1f, 0x0a, 0x0e, 0x52, 0x65, 0x63, 0x65, 0x69, 0x76, 0x65, 0x4d, 0x65, 0x73,
	0x73, 0x61, 0x67, 0x65, 0x12, 0x05, 0x2e, 0x44, 0x61, 0x74, 0x61, 0x1a, 0x06, 0x2e, 0x45, 0x6d,
	0x70, 0x74, 0x79, 0x42, 0x2a, 0x5a, 0x28, 0x67, 0x69, 0x74, 0x68, 0x75, 0x62, 0x2e, 0x63, 0x6f,
	0x6d, 0x2f, 0x79, 0x69, 0x73, 0x68, 0x61, 0x6b, 0x2d, 0x63, 0x73, 0x2f, 0x4e, 0x65, 0x77, 0x2d,
	0x50, 0x4b, 0x49, 0x63, 0x6c, 0x73, 0x2f, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x67, 0x65, 0x6e, 0x62,
	0x06, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x33,
}

var (
	file_CA_proto_rawDescOnce sync.Once
	file_CA_proto_rawDescData = file_CA_proto_rawDesc
)

func file_CA_proto_rawDescGZIP() []byte {
	file_CA_proto_rawDescOnce.Do(func() {
		file_CA_proto_rawDescData = protoimpl.X.CompressGZIP(file_CA_proto_rawDescData)
	})
	return file_CA_proto_rawDescData
}

var file_CA_proto_msgTypes = make([]protoimpl.MessageInfo, 7)
var file_CA_proto_goTypes = []any{
	(*CertificateRequest)(nil), // 0: CertificateRequest
	(*CertficateResponse)(nil), // 1: CertficateResponse
	(*CAPublicKey)(nil),        // 2: CAPublicKey
	(*Empty)(nil),              // 3: Empty
	(*InitialMessage)(nil),     // 4: InitialMessage
	(*SubsequentMessage)(nil),  // 5: SubsequentMessage
	(*Data)(nil),               // 6: Data
}
var file_CA_proto_depIdxs = []int32{
	1,  // 0: InitialMessage.sender_certificate:type_name -> CertficateResponse
	4,  // 1: Data.initial_message:type_name -> InitialMessage
	5,  // 2: Data.subsequent_message:type_name -> SubsequentMessage
	0,  // 3: CAService.IssueCertificate:input_type -> CertificateRequest
	3,  // 4: CAService.GetPublicKey:input_type -> Empty
	3,  // 5: PartyAService.SendCertificate:input_type -> Empty
	1,  // 6: PartyAService.verifyCertificate:input_type -> CertficateResponse
	6,  // 7: PartyAService.ReceiveMessage:input_type -> Data
	3,  // 8: PartyBService.SendCertificate:input_type -> Empty
	1,  // 9: PartyBService.verifyCertificate:input_type -> CertficateResponse
	6,  // 10: PartyBService.ReceiveMessage:input_type -> Data
	1,  // 11: CAService.IssueCertificate:output_type -> CertficateResponse
	2,  // 12: CAService.GetPublicKey:output_type -> CAPublicKey
	1,  // 13: PartyAService.SendCertificate:output_type -> CertficateResponse
	3,  // 14: PartyAService.verifyCertificate:output_type -> Empty
	3,  // 15: PartyAService.ReceiveMessage:output_type -> Empty
	1,  // 16: PartyBService.SendCertificate:output_type -> CertficateResponse
	3,  // 17: PartyBService.verifyCertificate:output_type -> Empty
	3,  // 18: PartyBService.ReceiveMessage:output_type -> Empty
	11, // [11:19] is the sub-list for method output_type
	3,  // [3:11] is the sub-list for method input_type
	3,  // [3:3] is the sub-list for extension type_name
	3,  // [3:3] is the sub-list for extension extendee
	0,  // [0:3] is the sub-list for field type_name
}

func init() { file_CA_proto_init() }
func file_CA_proto_init() {
	if File_CA_proto != nil {
		return
	}
	file_CA_proto_msgTypes[6].OneofWrappers = []any{
		(*Data_InitialMessage)(nil),
		(*Data_SubsequentMessage)(nil),
	}
	type x struct{}
	out := protoimpl.TypeBuilder{
		File: protoimpl.DescBuilder{
			GoPackagePath: reflect.TypeOf(x{}).PkgPath(),
			RawDescriptor: file_CA_proto_rawDesc,
			NumEnums:      0,
			NumMessages:   7,
			NumExtensions: 0,
			NumServices:   3,
		},
		GoTypes:           file_CA_proto_goTypes,
		DependencyIndexes: file_CA_proto_depIdxs,
		MessageInfos:      file_CA_proto_msgTypes,
	}.Build()
	File_CA_proto = out.File
	file_CA_proto_rawDesc = nil
	file_CA_proto_goTypes = nil
	file_CA_proto_depIdxs = nil
}
