// Code generated by protoc-gen-go-grpc. DO NOT EDIT.
// versions:
// - protoc-gen-go-grpc v1.5.1
// - protoc             v5.28.1
// source: CA.proto

package protogen

import (
	context "context"
	grpc "google.golang.org/grpc"
	codes "google.golang.org/grpc/codes"
	status "google.golang.org/grpc/status"
)

// This is a compile-time assertion to ensure that this generated file
// is compatible with the grpc package it is being compiled against.
// Requires gRPC-Go v1.64.0 or later.
const _ = grpc.SupportPackageIsVersion9

const (
	CAService_IssueCertificate_FullMethodName = "/CAService/IssueCertificate"
	CAService_GetPublicKey_FullMethodName     = "/CAService/GetPublicKey"
)

// CAServiceClient is the client API for CAService service.
//
// For semantics around ctx use and closing/ending streaming RPCs, please refer to https://pkg.go.dev/google.golang.org/grpc/?tab=doc#ClientConn.NewStream.
type CAServiceClient interface {
	IssueCertificate(ctx context.Context, in *CertificateRequest, opts ...grpc.CallOption) (*CertficateResponse, error)
	GetPublicKey(ctx context.Context, in *Empty, opts ...grpc.CallOption) (*CAPublicKey, error)
}

type cAServiceClient struct {
	cc grpc.ClientConnInterface
}

func NewCAServiceClient(cc grpc.ClientConnInterface) CAServiceClient {
	return &cAServiceClient{cc}
}

func (c *cAServiceClient) IssueCertificate(ctx context.Context, in *CertificateRequest, opts ...grpc.CallOption) (*CertficateResponse, error) {
	cOpts := append([]grpc.CallOption{grpc.StaticMethod()}, opts...)
	out := new(CertficateResponse)
	err := c.cc.Invoke(ctx, CAService_IssueCertificate_FullMethodName, in, out, cOpts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *cAServiceClient) GetPublicKey(ctx context.Context, in *Empty, opts ...grpc.CallOption) (*CAPublicKey, error) {
	cOpts := append([]grpc.CallOption{grpc.StaticMethod()}, opts...)
	out := new(CAPublicKey)
	err := c.cc.Invoke(ctx, CAService_GetPublicKey_FullMethodName, in, out, cOpts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

// CAServiceServer is the server API for CAService service.
// All implementations must embed UnimplementedCAServiceServer
// for forward compatibility.
type CAServiceServer interface {
	IssueCertificate(context.Context, *CertificateRequest) (*CertficateResponse, error)
	GetPublicKey(context.Context, *Empty) (*CAPublicKey, error)
	mustEmbedUnimplementedCAServiceServer()
}

// UnimplementedCAServiceServer must be embedded to have
// forward compatible implementations.
//
// NOTE: this should be embedded by value instead of pointer to avoid a nil
// pointer dereference when methods are called.
type UnimplementedCAServiceServer struct{}

func (UnimplementedCAServiceServer) IssueCertificate(context.Context, *CertificateRequest) (*CertficateResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method IssueCertificate not implemented")
}
func (UnimplementedCAServiceServer) GetPublicKey(context.Context, *Empty) (*CAPublicKey, error) {
	return nil, status.Errorf(codes.Unimplemented, "method GetPublicKey not implemented")
}
func (UnimplementedCAServiceServer) mustEmbedUnimplementedCAServiceServer() {}
func (UnimplementedCAServiceServer) testEmbeddedByValue()                   {}

// UnsafeCAServiceServer may be embedded to opt out of forward compatibility for this service.
// Use of this interface is not recommended, as added methods to CAServiceServer will
// result in compilation errors.
type UnsafeCAServiceServer interface {
	mustEmbedUnimplementedCAServiceServer()
}

func RegisterCAServiceServer(s grpc.ServiceRegistrar, srv CAServiceServer) {
	// If the following call pancis, it indicates UnimplementedCAServiceServer was
	// embedded by pointer and is nil.  This will cause panics if an
	// unimplemented method is ever invoked, so we test this at initialization
	// time to prevent it from happening at runtime later due to I/O.
	if t, ok := srv.(interface{ testEmbeddedByValue() }); ok {
		t.testEmbeddedByValue()
	}
	s.RegisterService(&CAService_ServiceDesc, srv)
}

func _CAService_IssueCertificate_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(CertificateRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(CAServiceServer).IssueCertificate(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: CAService_IssueCertificate_FullMethodName,
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(CAServiceServer).IssueCertificate(ctx, req.(*CertificateRequest))
	}
	return interceptor(ctx, in, info, handler)
}

func _CAService_GetPublicKey_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(Empty)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(CAServiceServer).GetPublicKey(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: CAService_GetPublicKey_FullMethodName,
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(CAServiceServer).GetPublicKey(ctx, req.(*Empty))
	}
	return interceptor(ctx, in, info, handler)
}

// CAService_ServiceDesc is the grpc.ServiceDesc for CAService service.
// It's only intended for direct use with grpc.RegisterService,
// and not to be introspected or modified (even as a copy)
var CAService_ServiceDesc = grpc.ServiceDesc{
	ServiceName: "CAService",
	HandlerType: (*CAServiceServer)(nil),
	Methods: []grpc.MethodDesc{
		{
			MethodName: "IssueCertificate",
			Handler:    _CAService_IssueCertificate_Handler,
		},
		{
			MethodName: "GetPublicKey",
			Handler:    _CAService_GetPublicKey_Handler,
		},
	},
	Streams:  []grpc.StreamDesc{},
	Metadata: "CA.proto",
}

const (
	PartyAService_SendCertificate_FullMethodName   = "/PartyAService/SendCertificate"
	PartyAService_VerifyCertificate_FullMethodName = "/PartyAService/verifyCertificate"
	PartyAService_ReceiveMessage_FullMethodName    = "/PartyAService/ReceiveMessage"
)

// PartyAServiceClient is the client API for PartyAService service.
//
// For semantics around ctx use and closing/ending streaming RPCs, please refer to https://pkg.go.dev/google.golang.org/grpc/?tab=doc#ClientConn.NewStream.
type PartyAServiceClient interface {
	SendCertificate(ctx context.Context, in *Empty, opts ...grpc.CallOption) (*CertficateResponse, error)
	VerifyCertificate(ctx context.Context, in *CertficateResponse, opts ...grpc.CallOption) (*Empty, error)
	ReceiveMessage(ctx context.Context, in *Data, opts ...grpc.CallOption) (*Empty, error)
}

type partyAServiceClient struct {
	cc grpc.ClientConnInterface
}

func NewPartyAServiceClient(cc grpc.ClientConnInterface) PartyAServiceClient {
	return &partyAServiceClient{cc}
}

func (c *partyAServiceClient) SendCertificate(ctx context.Context, in *Empty, opts ...grpc.CallOption) (*CertficateResponse, error) {
	cOpts := append([]grpc.CallOption{grpc.StaticMethod()}, opts...)
	out := new(CertficateResponse)
	err := c.cc.Invoke(ctx, PartyAService_SendCertificate_FullMethodName, in, out, cOpts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *partyAServiceClient) VerifyCertificate(ctx context.Context, in *CertficateResponse, opts ...grpc.CallOption) (*Empty, error) {
	cOpts := append([]grpc.CallOption{grpc.StaticMethod()}, opts...)
	out := new(Empty)
	err := c.cc.Invoke(ctx, PartyAService_VerifyCertificate_FullMethodName, in, out, cOpts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *partyAServiceClient) ReceiveMessage(ctx context.Context, in *Data, opts ...grpc.CallOption) (*Empty, error) {
	cOpts := append([]grpc.CallOption{grpc.StaticMethod()}, opts...)
	out := new(Empty)
	err := c.cc.Invoke(ctx, PartyAService_ReceiveMessage_FullMethodName, in, out, cOpts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

// PartyAServiceServer is the server API for PartyAService service.
// All implementations must embed UnimplementedPartyAServiceServer
// for forward compatibility.
type PartyAServiceServer interface {
	SendCertificate(context.Context, *Empty) (*CertficateResponse, error)
	VerifyCertificate(context.Context, *CertficateResponse) (*Empty, error)
	ReceiveMessage(context.Context, *Data) (*Empty, error)
	mustEmbedUnimplementedPartyAServiceServer()
}

// UnimplementedPartyAServiceServer must be embedded to have
// forward compatible implementations.
//
// NOTE: this should be embedded by value instead of pointer to avoid a nil
// pointer dereference when methods are called.
type UnimplementedPartyAServiceServer struct{}

func (UnimplementedPartyAServiceServer) SendCertificate(context.Context, *Empty) (*CertficateResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method SendCertificate not implemented")
}
func (UnimplementedPartyAServiceServer) VerifyCertificate(context.Context, *CertficateResponse) (*Empty, error) {
	return nil, status.Errorf(codes.Unimplemented, "method VerifyCertificate not implemented")
}
func (UnimplementedPartyAServiceServer) ReceiveMessage(context.Context, *Data) (*Empty, error) {
	return nil, status.Errorf(codes.Unimplemented, "method ReceiveMessage not implemented")
}
func (UnimplementedPartyAServiceServer) mustEmbedUnimplementedPartyAServiceServer() {}
func (UnimplementedPartyAServiceServer) testEmbeddedByValue()                       {}

// UnsafePartyAServiceServer may be embedded to opt out of forward compatibility for this service.
// Use of this interface is not recommended, as added methods to PartyAServiceServer will
// result in compilation errors.
type UnsafePartyAServiceServer interface {
	mustEmbedUnimplementedPartyAServiceServer()
}

func RegisterPartyAServiceServer(s grpc.ServiceRegistrar, srv PartyAServiceServer) {
	// If the following call pancis, it indicates UnimplementedPartyAServiceServer was
	// embedded by pointer and is nil.  This will cause panics if an
	// unimplemented method is ever invoked, so we test this at initialization
	// time to prevent it from happening at runtime later due to I/O.
	if t, ok := srv.(interface{ testEmbeddedByValue() }); ok {
		t.testEmbeddedByValue()
	}
	s.RegisterService(&PartyAService_ServiceDesc, srv)
}

func _PartyAService_SendCertificate_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(Empty)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(PartyAServiceServer).SendCertificate(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: PartyAService_SendCertificate_FullMethodName,
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(PartyAServiceServer).SendCertificate(ctx, req.(*Empty))
	}
	return interceptor(ctx, in, info, handler)
}

func _PartyAService_VerifyCertificate_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(CertficateResponse)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(PartyAServiceServer).VerifyCertificate(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: PartyAService_VerifyCertificate_FullMethodName,
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(PartyAServiceServer).VerifyCertificate(ctx, req.(*CertficateResponse))
	}
	return interceptor(ctx, in, info, handler)
}

func _PartyAService_ReceiveMessage_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(Data)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(PartyAServiceServer).ReceiveMessage(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: PartyAService_ReceiveMessage_FullMethodName,
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(PartyAServiceServer).ReceiveMessage(ctx, req.(*Data))
	}
	return interceptor(ctx, in, info, handler)
}

// PartyAService_ServiceDesc is the grpc.ServiceDesc for PartyAService service.
// It's only intended for direct use with grpc.RegisterService,
// and not to be introspected or modified (even as a copy)
var PartyAService_ServiceDesc = grpc.ServiceDesc{
	ServiceName: "PartyAService",
	HandlerType: (*PartyAServiceServer)(nil),
	Methods: []grpc.MethodDesc{
		{
			MethodName: "SendCertificate",
			Handler:    _PartyAService_SendCertificate_Handler,
		},
		{
			MethodName: "verifyCertificate",
			Handler:    _PartyAService_VerifyCertificate_Handler,
		},
		{
			MethodName: "ReceiveMessage",
			Handler:    _PartyAService_ReceiveMessage_Handler,
		},
	},
	Streams:  []grpc.StreamDesc{},
	Metadata: "CA.proto",
}

const (
	PartyBService_SendCertificate_FullMethodName   = "/PartyBService/SendCertificate"
	PartyBService_VerifyCertificate_FullMethodName = "/PartyBService/verifyCertificate"
	PartyBService_ReceiveMessage_FullMethodName    = "/PartyBService/ReceiveMessage"
)

// PartyBServiceClient is the client API for PartyBService service.
//
// For semantics around ctx use and closing/ending streaming RPCs, please refer to https://pkg.go.dev/google.golang.org/grpc/?tab=doc#ClientConn.NewStream.
type PartyBServiceClient interface {
	SendCertificate(ctx context.Context, in *Empty, opts ...grpc.CallOption) (*CertficateResponse, error)
	VerifyCertificate(ctx context.Context, in *CertficateResponse, opts ...grpc.CallOption) (*Empty, error)
	ReceiveMessage(ctx context.Context, in *Data, opts ...grpc.CallOption) (*Empty, error)
}

type partyBServiceClient struct {
	cc grpc.ClientConnInterface
}

func NewPartyBServiceClient(cc grpc.ClientConnInterface) PartyBServiceClient {
	return &partyBServiceClient{cc}
}

func (c *partyBServiceClient) SendCertificate(ctx context.Context, in *Empty, opts ...grpc.CallOption) (*CertficateResponse, error) {
	cOpts := append([]grpc.CallOption{grpc.StaticMethod()}, opts...)
	out := new(CertficateResponse)
	err := c.cc.Invoke(ctx, PartyBService_SendCertificate_FullMethodName, in, out, cOpts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *partyBServiceClient) VerifyCertificate(ctx context.Context, in *CertficateResponse, opts ...grpc.CallOption) (*Empty, error) {
	cOpts := append([]grpc.CallOption{grpc.StaticMethod()}, opts...)
	out := new(Empty)
	err := c.cc.Invoke(ctx, PartyBService_VerifyCertificate_FullMethodName, in, out, cOpts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *partyBServiceClient) ReceiveMessage(ctx context.Context, in *Data, opts ...grpc.CallOption) (*Empty, error) {
	cOpts := append([]grpc.CallOption{grpc.StaticMethod()}, opts...)
	out := new(Empty)
	err := c.cc.Invoke(ctx, PartyBService_ReceiveMessage_FullMethodName, in, out, cOpts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

// PartyBServiceServer is the server API for PartyBService service.
// All implementations must embed UnimplementedPartyBServiceServer
// for forward compatibility.
type PartyBServiceServer interface {
	SendCertificate(context.Context, *Empty) (*CertficateResponse, error)
	VerifyCertificate(context.Context, *CertficateResponse) (*Empty, error)
	ReceiveMessage(context.Context, *Data) (*Empty, error)
	mustEmbedUnimplementedPartyBServiceServer()
}

// UnimplementedPartyBServiceServer must be embedded to have
// forward compatible implementations.
//
// NOTE: this should be embedded by value instead of pointer to avoid a nil
// pointer dereference when methods are called.
type UnimplementedPartyBServiceServer struct{}

func (UnimplementedPartyBServiceServer) SendCertificate(context.Context, *Empty) (*CertficateResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method SendCertificate not implemented")
}
func (UnimplementedPartyBServiceServer) VerifyCertificate(context.Context, *CertficateResponse) (*Empty, error) {
	return nil, status.Errorf(codes.Unimplemented, "method VerifyCertificate not implemented")
}
func (UnimplementedPartyBServiceServer) ReceiveMessage(context.Context, *Data) (*Empty, error) {
	return nil, status.Errorf(codes.Unimplemented, "method ReceiveMessage not implemented")
}
func (UnimplementedPartyBServiceServer) mustEmbedUnimplementedPartyBServiceServer() {}
func (UnimplementedPartyBServiceServer) testEmbeddedByValue()                       {}

// UnsafePartyBServiceServer may be embedded to opt out of forward compatibility for this service.
// Use of this interface is not recommended, as added methods to PartyBServiceServer will
// result in compilation errors.
type UnsafePartyBServiceServer interface {
	mustEmbedUnimplementedPartyBServiceServer()
}

func RegisterPartyBServiceServer(s grpc.ServiceRegistrar, srv PartyBServiceServer) {
	// If the following call pancis, it indicates UnimplementedPartyBServiceServer was
	// embedded by pointer and is nil.  This will cause panics if an
	// unimplemented method is ever invoked, so we test this at initialization
	// time to prevent it from happening at runtime later due to I/O.
	if t, ok := srv.(interface{ testEmbeddedByValue() }); ok {
		t.testEmbeddedByValue()
	}
	s.RegisterService(&PartyBService_ServiceDesc, srv)
}

func _PartyBService_SendCertificate_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(Empty)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(PartyBServiceServer).SendCertificate(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: PartyBService_SendCertificate_FullMethodName,
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(PartyBServiceServer).SendCertificate(ctx, req.(*Empty))
	}
	return interceptor(ctx, in, info, handler)
}

func _PartyBService_VerifyCertificate_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(CertficateResponse)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(PartyBServiceServer).VerifyCertificate(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: PartyBService_VerifyCertificate_FullMethodName,
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(PartyBServiceServer).VerifyCertificate(ctx, req.(*CertficateResponse))
	}
	return interceptor(ctx, in, info, handler)
}

func _PartyBService_ReceiveMessage_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(Data)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(PartyBServiceServer).ReceiveMessage(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: PartyBService_ReceiveMessage_FullMethodName,
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(PartyBServiceServer).ReceiveMessage(ctx, req.(*Data))
	}
	return interceptor(ctx, in, info, handler)
}

// PartyBService_ServiceDesc is the grpc.ServiceDesc for PartyBService service.
// It's only intended for direct use with grpc.RegisterService,
// and not to be introspected or modified (even as a copy)
var PartyBService_ServiceDesc = grpc.ServiceDesc{
	ServiceName: "PartyBService",
	HandlerType: (*PartyBServiceServer)(nil),
	Methods: []grpc.MethodDesc{
		{
			MethodName: "SendCertificate",
			Handler:    _PartyBService_SendCertificate_Handler,
		},
		{
			MethodName: "verifyCertificate",
			Handler:    _PartyBService_VerifyCertificate_Handler,
		},
		{
			MethodName: "ReceiveMessage",
			Handler:    _PartyBService_ReceiveMessage_Handler,
		},
	},
	Streams:  []grpc.StreamDesc{},
	Metadata: "CA.proto",
}
