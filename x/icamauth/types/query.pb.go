// Code generated by protoc-gen-gogo. DO NOT EDIT.
// source: gaia/icamauth/v1beta1/query.proto

package types

import (
	context "context"
	fmt "fmt"
	io "io"
	math "math"
	math_bits "math/bits"

	_ "github.com/gogo/protobuf/gogoproto"
	grpc1 "github.com/gogo/protobuf/grpc"
	proto "github.com/gogo/protobuf/proto"
	_ "google.golang.org/genproto/googleapis/api/annotations"
	grpc "google.golang.org/grpc"
	codes "google.golang.org/grpc/codes"
	status "google.golang.org/grpc/status"
)

// Reference imports to suppress errors if they are not otherwise used.
var _ = proto.Marshal
var _ = fmt.Errorf
var _ = math.Inf

// This is a compile-time assertion to ensure that this generated file
// is compatible with the proto package it is being compiled against.
// A compilation error at this line likely means your copy of the
// proto package needs to be updated.
const _ = proto.GoGoProtoPackageIsVersion3 // please upgrade the proto package

// QueryInterchainAccountRequest is the request type for the Query/InterchainAccountAddress RPC
type QueryInterchainAccountRequest struct {
	Owner        string `protobuf:"bytes,1,opt,name=owner,proto3" json:"owner,omitempty"`
	ConnectionId string `protobuf:"bytes,2,opt,name=connection_id,json=connectionId,proto3" json:"connection_id,omitempty" yaml:"connection_id"`
}

func (m *QueryInterchainAccountRequest) Reset()         { *m = QueryInterchainAccountRequest{} }
func (m *QueryInterchainAccountRequest) String() string { return proto.CompactTextString(m) }
func (*QueryInterchainAccountRequest) ProtoMessage()    {}
func (*QueryInterchainAccountRequest) Descriptor() ([]byte, []int) {
	return fileDescriptor_2cf727725a0b026b, []int{0}
}
func (m *QueryInterchainAccountRequest) XXX_Unmarshal(b []byte) error {
	return m.Unmarshal(b)
}
func (m *QueryInterchainAccountRequest) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	if deterministic {
		return xxx_messageInfo_QueryInterchainAccountRequest.Marshal(b, m, deterministic)
	} else {
		b = b[:cap(b)]
		n, err := m.MarshalToSizedBuffer(b)
		if err != nil {
			return nil, err
		}
		return b[:n], nil
	}
}
func (m *QueryInterchainAccountRequest) XXX_Merge(src proto.Message) {
	xxx_messageInfo_QueryInterchainAccountRequest.Merge(m, src)
}
func (m *QueryInterchainAccountRequest) XXX_Size() int {
	return m.Size()
}
func (m *QueryInterchainAccountRequest) XXX_DiscardUnknown() {
	xxx_messageInfo_QueryInterchainAccountRequest.DiscardUnknown(m)
}

var xxx_messageInfo_QueryInterchainAccountRequest proto.InternalMessageInfo

func (m *QueryInterchainAccountRequest) GetOwner() string {
	if m != nil {
		return m.Owner
	}
	return ""
}

func (m *QueryInterchainAccountRequest) GetConnectionId() string {
	if m != nil {
		return m.ConnectionId
	}
	return ""
}

// QueryInterchainAccountResponse the response type for the Query/InterchainAccountAddress RPC
type QueryInterchainAccountResponse struct {
	InterchainAccountAddress string `protobuf:"bytes,1,opt,name=interchain_account_address,json=interchainAccountAddress,proto3" json:"interchain_account_address,omitempty" yaml:"interchain_account_address"`
}

func (m *QueryInterchainAccountResponse) Reset()         { *m = QueryInterchainAccountResponse{} }
func (m *QueryInterchainAccountResponse) String() string { return proto.CompactTextString(m) }
func (*QueryInterchainAccountResponse) ProtoMessage()    {}
func (*QueryInterchainAccountResponse) Descriptor() ([]byte, []int) {
	return fileDescriptor_2cf727725a0b026b, []int{1}
}
func (m *QueryInterchainAccountResponse) XXX_Unmarshal(b []byte) error {
	return m.Unmarshal(b)
}
func (m *QueryInterchainAccountResponse) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	if deterministic {
		return xxx_messageInfo_QueryInterchainAccountResponse.Marshal(b, m, deterministic)
	} else {
		b = b[:cap(b)]
		n, err := m.MarshalToSizedBuffer(b)
		if err != nil {
			return nil, err
		}
		return b[:n], nil
	}
}
func (m *QueryInterchainAccountResponse) XXX_Merge(src proto.Message) {
	xxx_messageInfo_QueryInterchainAccountResponse.Merge(m, src)
}
func (m *QueryInterchainAccountResponse) XXX_Size() int {
	return m.Size()
}
func (m *QueryInterchainAccountResponse) XXX_DiscardUnknown() {
	xxx_messageInfo_QueryInterchainAccountResponse.DiscardUnknown(m)
}

var xxx_messageInfo_QueryInterchainAccountResponse proto.InternalMessageInfo

func (m *QueryInterchainAccountResponse) GetInterchainAccountAddress() string {
	if m != nil {
		return m.InterchainAccountAddress
	}
	return ""
}

func init() {
	proto.RegisterType((*QueryInterchainAccountRequest)(nil), "gaia.icamauth.v1beta1.QueryInterchainAccountRequest")
	proto.RegisterType((*QueryInterchainAccountResponse)(nil), "gaia.icamauth.v1beta1.QueryInterchainAccountResponse")
}

func init() { proto.RegisterFile("gaia/icamauth/v1beta1/query.proto", fileDescriptor_2cf727725a0b026b) }

var fileDescriptor_2cf727725a0b026b = []byte{
	// 376 bytes of a gzipped FileDescriptorProto
	0x1f, 0x8b, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0xff, 0x94, 0x52, 0x41, 0x6b, 0xe2, 0x40,
	0x14, 0x76, 0x04, 0x17, 0x76, 0xd8, 0x3d, 0x6c, 0x70, 0x21, 0x84, 0xdd, 0xb8, 0x06, 0x96, 0xdd,
	0x53, 0x06, 0x77, 0xdb, 0x4b, 0xa1, 0x07, 0xbd, 0x79, 0x6c, 0xe8, 0xc9, 0x8b, 0x8c, 0x93, 0x21,
	0x0e, 0x98, 0x79, 0x31, 0x33, 0x69, 0x2b, 0xe2, 0xa5, 0xd0, 0x7b, 0xa1, 0x7f, 0xaa, 0x47, 0xa1,
	0x97, 0x1e, 0x8a, 0x14, 0x2d, 0xfd, 0x01, 0xfe, 0x82, 0x92, 0x4c, 0x5b, 0xb1, 0x6a, 0xa1, 0xa7,
	0x99, 0xc7, 0xf7, 0xcd, 0xfb, 0xbe, 0xf7, 0xcd, 0xc3, 0xf5, 0x88, 0x0a, 0x4a, 0x04, 0xa3, 0x31,
	0xcd, 0x74, 0x9f, 0x9c, 0x34, 0x7a, 0x5c, 0xd3, 0x06, 0x19, 0x66, 0x3c, 0x1d, 0xf9, 0x49, 0x0a,
	0x1a, 0xac, 0xef, 0x39, 0xc5, 0x7f, 0xa1, 0xf8, 0xcf, 0x14, 0xa7, 0x1a, 0x41, 0x04, 0x05, 0x83,
	0xe4, 0x37, 0x43, 0x76, 0x7e, 0x44, 0x00, 0xd1, 0x80, 0x13, 0x9a, 0x08, 0x42, 0xa5, 0x04, 0x4d,
	0xb5, 0x00, 0xa9, 0x0c, 0xea, 0x69, 0xfc, 0xf3, 0x28, 0xef, 0xdc, 0x96, 0x9a, 0xa7, 0xac, 0x4f,
	0x85, 0x6c, 0x32, 0x06, 0x99, 0xd4, 0x01, 0x1f, 0x66, 0x5c, 0x69, 0xab, 0x8a, 0x2b, 0x70, 0x2a,
	0x79, 0x6a, 0xa3, 0x5f, 0xe8, 0xef, 0xe7, 0xc0, 0x14, 0xd6, 0x21, 0xfe, 0xca, 0x40, 0x4a, 0xce,
	0xf2, 0x5e, 0x5d, 0x11, 0xda, 0xe5, 0x1c, 0x6d, 0xd9, 0xcb, 0x59, 0xad, 0x3a, 0xa2, 0xf1, 0xe0,
	0xc0, 0x5b, 0x83, 0xbd, 0xe0, 0xcb, 0xaa, 0x6e, 0x87, 0xde, 0x05, 0xc2, 0xee, 0x2e, 0x59, 0x95,
	0x80, 0x54, 0xdc, 0x62, 0xd8, 0x11, 0xaf, 0x60, 0x97, 0x1a, 0xb4, 0x4b, 0xc3, 0x30, 0xe5, 0x4a,
	0x19, 0x33, 0xad, 0xdf, 0xcb, 0x59, 0xad, 0x6e, 0xe4, 0x76, 0x73, 0xbd, 0xc0, 0x16, 0x6f, 0x55,
	0x9a, 0x06, 0xfa, 0xf7, 0x88, 0x70, 0xa5, 0xf0, 0x61, 0xdd, 0x21, 0xfc, 0x6d, 0xc3, 0x8c, 0xb5,
	0xe7, 0x6f, 0x4d, 0xda, 0x7f, 0x37, 0x32, 0x67, 0xff, 0x83, 0xaf, 0xcc, 0xc4, 0x5e, 0xe7, 0xfc,
	0xe6, 0xe1, 0xaa, 0x7c, 0x6c, 0x05, 0x64, 0xfb, 0x06, 0x6c, 0x8e, 0x48, 0x8a, 0xcf, 0x20, 0xe3,
	0xe2, 0x98, 0x90, 0x55, 0xc4, 0x64, 0xbc, 0x16, 0xff, 0xa4, 0xd5, 0xbc, 0x9e, 0xbb, 0x68, 0x3a,
	0x77, 0xd1, 0xfd, 0xdc, 0x45, 0x97, 0x0b, 0xb7, 0x34, 0x5d, 0xb8, 0xa5, 0xdb, 0x85, 0x5b, 0xea,
	0xfc, 0x89, 0x84, 0xee, 0x67, 0x3d, 0x9f, 0x41, 0x4c, 0x18, 0xa8, 0x18, 0x94, 0x91, 0x3f, 0x5b,
	0x19, 0xd0, 0xa3, 0x84, 0xab, 0xde, 0xa7, 0x62, 0x61, 0xfe, 0x3f, 0x05, 0x00, 0x00, 0xff, 0xff,
	0x16, 0x91, 0x9a, 0x26, 0xa0, 0x02, 0x00, 0x00,
}

// Reference imports to suppress errors if they are not otherwise used.
var _ context.Context
var _ grpc.ClientConn

// This is a compile-time assertion to ensure that this generated file
// is compatible with the grpc package it is being compiled against.
const _ = grpc.SupportPackageIsVersion4

// QueryClient is the client API for Query service.
//
// For semantics around ctx use and closing/ending streaming RPCs, please refer to https://godoc.org/google.golang.org/grpc#ClientConn.NewStream.
type QueryClient interface {
	// QueryInterchainAccount returns the interchain account for given owner address on a given connection pair
	InterchainAccount(ctx context.Context, in *QueryInterchainAccountRequest, opts ...grpc.CallOption) (*QueryInterchainAccountResponse, error)
}

type queryClient struct {
	cc grpc1.ClientConn
}

func NewQueryClient(cc grpc1.ClientConn) QueryClient {
	return &queryClient{cc}
}

func (c *queryClient) InterchainAccount(ctx context.Context, in *QueryInterchainAccountRequest, opts ...grpc.CallOption) (*QueryInterchainAccountResponse, error) {
	out := new(QueryInterchainAccountResponse)
	err := c.cc.Invoke(ctx, "/gaia.icamauth.v1beta1.Query/InterchainAccount", in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

// QueryServer is the server API for Query service.
type QueryServer interface {
	// QueryInterchainAccount returns the interchain account for given owner address on a given connection pair
	InterchainAccount(context.Context, *QueryInterchainAccountRequest) (*QueryInterchainAccountResponse, error)
}

// UnimplementedQueryServer can be embedded to have forward compatible implementations.
type UnimplementedQueryServer struct {
}

func (*UnimplementedQueryServer) InterchainAccount(ctx context.Context, req *QueryInterchainAccountRequest) (*QueryInterchainAccountResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method InterchainAccount not implemented")
}

func RegisterQueryServer(s grpc1.Server, srv QueryServer) {
	s.RegisterService(&_Query_serviceDesc, srv)
}

func _Query_InterchainAccount_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(QueryInterchainAccountRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(QueryServer).InterchainAccount(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: "/gaia.icamauth.v1beta1.Query/InterchainAccount",
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(QueryServer).InterchainAccount(ctx, req.(*QueryInterchainAccountRequest))
	}
	return interceptor(ctx, in, info, handler)
}

var _Query_serviceDesc = grpc.ServiceDesc{
	ServiceName: "gaia.icamauth.v1beta1.Query",
	HandlerType: (*QueryServer)(nil),
	Methods: []grpc.MethodDesc{
		{
			MethodName: "InterchainAccount",
			Handler:    _Query_InterchainAccount_Handler,
		},
	},
	Streams:  []grpc.StreamDesc{},
	Metadata: "gaia/icamauth/v1beta1/query.proto",
}

func (m *QueryInterchainAccountRequest) Marshal() (dAtA []byte, err error) {
	size := m.Size()
	dAtA = make([]byte, size)
	n, err := m.MarshalToSizedBuffer(dAtA[:size])
	if err != nil {
		return nil, err
	}
	return dAtA[:n], nil
}

func (m *QueryInterchainAccountRequest) MarshalTo(dAtA []byte) (int, error) {
	size := m.Size()
	return m.MarshalToSizedBuffer(dAtA[:size])
}

func (m *QueryInterchainAccountRequest) MarshalToSizedBuffer(dAtA []byte) (int, error) {
	i := len(dAtA)
	_ = i
	var l int
	_ = l
	if len(m.ConnectionId) > 0 {
		i -= len(m.ConnectionId)
		copy(dAtA[i:], m.ConnectionId)
		i = encodeVarintQuery(dAtA, i, uint64(len(m.ConnectionId)))
		i--
		dAtA[i] = 0x12
	}
	if len(m.Owner) > 0 {
		i -= len(m.Owner)
		copy(dAtA[i:], m.Owner)
		i = encodeVarintQuery(dAtA, i, uint64(len(m.Owner)))
		i--
		dAtA[i] = 0xa
	}
	return len(dAtA) - i, nil
}

func (m *QueryInterchainAccountResponse) Marshal() (dAtA []byte, err error) {
	size := m.Size()
	dAtA = make([]byte, size)
	n, err := m.MarshalToSizedBuffer(dAtA[:size])
	if err != nil {
		return nil, err
	}
	return dAtA[:n], nil
}

func (m *QueryInterchainAccountResponse) MarshalTo(dAtA []byte) (int, error) {
	size := m.Size()
	return m.MarshalToSizedBuffer(dAtA[:size])
}

func (m *QueryInterchainAccountResponse) MarshalToSizedBuffer(dAtA []byte) (int, error) {
	i := len(dAtA)
	_ = i
	var l int
	_ = l
	if len(m.InterchainAccountAddress) > 0 {
		i -= len(m.InterchainAccountAddress)
		copy(dAtA[i:], m.InterchainAccountAddress)
		i = encodeVarintQuery(dAtA, i, uint64(len(m.InterchainAccountAddress)))
		i--
		dAtA[i] = 0xa
	}
	return len(dAtA) - i, nil
}

func encodeVarintQuery(dAtA []byte, offset int, v uint64) int {
	offset -= sovQuery(v)
	base := offset
	for v >= 1<<7 {
		dAtA[offset] = uint8(v&0x7f | 0x80)
		v >>= 7
		offset++
	}
	dAtA[offset] = uint8(v)
	return base
}
func (m *QueryInterchainAccountRequest) Size() (n int) {
	if m == nil {
		return 0
	}
	var l int
	_ = l
	l = len(m.Owner)
	if l > 0 {
		n += 1 + l + sovQuery(uint64(l))
	}
	l = len(m.ConnectionId)
	if l > 0 {
		n += 1 + l + sovQuery(uint64(l))
	}
	return n
}

func (m *QueryInterchainAccountResponse) Size() (n int) {
	if m == nil {
		return 0
	}
	var l int
	_ = l
	l = len(m.InterchainAccountAddress)
	if l > 0 {
		n += 1 + l + sovQuery(uint64(l))
	}
	return n
}

func sovQuery(x uint64) (n int) {
	return (math_bits.Len64(x|1) + 6) / 7
}
func sozQuery(x uint64) (n int) {
	return sovQuery(uint64((x << 1) ^ uint64((int64(x) >> 63))))
}
func (m *QueryInterchainAccountRequest) Unmarshal(dAtA []byte) error {
	l := len(dAtA)
	iNdEx := 0
	for iNdEx < l {
		preIndex := iNdEx
		var wire uint64
		for shift := uint(0); ; shift += 7 {
			if shift >= 64 {
				return ErrIntOverflowQuery
			}
			if iNdEx >= l {
				return io.ErrUnexpectedEOF
			}
			b := dAtA[iNdEx]
			iNdEx++
			wire |= uint64(b&0x7F) << shift
			if b < 0x80 {
				break
			}
		}
		fieldNum := int32(wire >> 3)
		wireType := int(wire & 0x7)
		if wireType == 4 {
			return fmt.Errorf("proto: QueryInterchainAccountRequest: wiretype end group for non-group")
		}
		if fieldNum <= 0 {
			return fmt.Errorf("proto: QueryInterchainAccountRequest: illegal tag %d (wire type %d)", fieldNum, wire)
		}
		switch fieldNum {
		case 1:
			if wireType != 2 {
				return fmt.Errorf("proto: wrong wireType = %d for field Owner", wireType)
			}
			var stringLen uint64
			for shift := uint(0); ; shift += 7 {
				if shift >= 64 {
					return ErrIntOverflowQuery
				}
				if iNdEx >= l {
					return io.ErrUnexpectedEOF
				}
				b := dAtA[iNdEx]
				iNdEx++
				stringLen |= uint64(b&0x7F) << shift
				if b < 0x80 {
					break
				}
			}
			intStringLen := int(stringLen)
			if intStringLen < 0 {
				return ErrInvalidLengthQuery
			}
			postIndex := iNdEx + intStringLen
			if postIndex < 0 {
				return ErrInvalidLengthQuery
			}
			if postIndex > l {
				return io.ErrUnexpectedEOF
			}
			m.Owner = string(dAtA[iNdEx:postIndex])
			iNdEx = postIndex
		case 2:
			if wireType != 2 {
				return fmt.Errorf("proto: wrong wireType = %d for field ConnectionId", wireType)
			}
			var stringLen uint64
			for shift := uint(0); ; shift += 7 {
				if shift >= 64 {
					return ErrIntOverflowQuery
				}
				if iNdEx >= l {
					return io.ErrUnexpectedEOF
				}
				b := dAtA[iNdEx]
				iNdEx++
				stringLen |= uint64(b&0x7F) << shift
				if b < 0x80 {
					break
				}
			}
			intStringLen := int(stringLen)
			if intStringLen < 0 {
				return ErrInvalidLengthQuery
			}
			postIndex := iNdEx + intStringLen
			if postIndex < 0 {
				return ErrInvalidLengthQuery
			}
			if postIndex > l {
				return io.ErrUnexpectedEOF
			}
			m.ConnectionId = string(dAtA[iNdEx:postIndex])
			iNdEx = postIndex
		default:
			iNdEx = preIndex
			skippy, err := skipQuery(dAtA[iNdEx:])
			if err != nil {
				return err
			}
			if (skippy < 0) || (iNdEx+skippy) < 0 {
				return ErrInvalidLengthQuery
			}
			if (iNdEx + skippy) > l {
				return io.ErrUnexpectedEOF
			}
			iNdEx += skippy
		}
	}

	if iNdEx > l {
		return io.ErrUnexpectedEOF
	}
	return nil
}
func (m *QueryInterchainAccountResponse) Unmarshal(dAtA []byte) error {
	l := len(dAtA)
	iNdEx := 0
	for iNdEx < l {
		preIndex := iNdEx
		var wire uint64
		for shift := uint(0); ; shift += 7 {
			if shift >= 64 {
				return ErrIntOverflowQuery
			}
			if iNdEx >= l {
				return io.ErrUnexpectedEOF
			}
			b := dAtA[iNdEx]
			iNdEx++
			wire |= uint64(b&0x7F) << shift
			if b < 0x80 {
				break
			}
		}
		fieldNum := int32(wire >> 3)
		wireType := int(wire & 0x7)
		if wireType == 4 {
			return fmt.Errorf("proto: QueryInterchainAccountResponse: wiretype end group for non-group")
		}
		if fieldNum <= 0 {
			return fmt.Errorf("proto: QueryInterchainAccountResponse: illegal tag %d (wire type %d)", fieldNum, wire)
		}
		switch fieldNum {
		case 1:
			if wireType != 2 {
				return fmt.Errorf("proto: wrong wireType = %d for field InterchainAccountAddress", wireType)
			}
			var stringLen uint64
			for shift := uint(0); ; shift += 7 {
				if shift >= 64 {
					return ErrIntOverflowQuery
				}
				if iNdEx >= l {
					return io.ErrUnexpectedEOF
				}
				b := dAtA[iNdEx]
				iNdEx++
				stringLen |= uint64(b&0x7F) << shift
				if b < 0x80 {
					break
				}
			}
			intStringLen := int(stringLen)
			if intStringLen < 0 {
				return ErrInvalidLengthQuery
			}
			postIndex := iNdEx + intStringLen
			if postIndex < 0 {
				return ErrInvalidLengthQuery
			}
			if postIndex > l {
				return io.ErrUnexpectedEOF
			}
			m.InterchainAccountAddress = string(dAtA[iNdEx:postIndex])
			iNdEx = postIndex
		default:
			iNdEx = preIndex
			skippy, err := skipQuery(dAtA[iNdEx:])
			if err != nil {
				return err
			}
			if (skippy < 0) || (iNdEx+skippy) < 0 {
				return ErrInvalidLengthQuery
			}
			if (iNdEx + skippy) > l {
				return io.ErrUnexpectedEOF
			}
			iNdEx += skippy
		}
	}

	if iNdEx > l {
		return io.ErrUnexpectedEOF
	}
	return nil
}
func skipQuery(dAtA []byte) (n int, err error) {
	l := len(dAtA)
	iNdEx := 0
	depth := 0
	for iNdEx < l {
		var wire uint64
		for shift := uint(0); ; shift += 7 {
			if shift >= 64 {
				return 0, ErrIntOverflowQuery
			}
			if iNdEx >= l {
				return 0, io.ErrUnexpectedEOF
			}
			b := dAtA[iNdEx]
			iNdEx++
			wire |= (uint64(b) & 0x7F) << shift
			if b < 0x80 {
				break
			}
		}
		wireType := int(wire & 0x7)
		switch wireType {
		case 0:
			for shift := uint(0); ; shift += 7 {
				if shift >= 64 {
					return 0, ErrIntOverflowQuery
				}
				if iNdEx >= l {
					return 0, io.ErrUnexpectedEOF
				}
				iNdEx++
				if dAtA[iNdEx-1] < 0x80 {
					break
				}
			}
		case 1:
			iNdEx += 8
		case 2:
			var length int
			for shift := uint(0); ; shift += 7 {
				if shift >= 64 {
					return 0, ErrIntOverflowQuery
				}
				if iNdEx >= l {
					return 0, io.ErrUnexpectedEOF
				}
				b := dAtA[iNdEx]
				iNdEx++
				length |= (int(b) & 0x7F) << shift
				if b < 0x80 {
					break
				}
			}
			if length < 0 {
				return 0, ErrInvalidLengthQuery
			}
			iNdEx += length
		case 3:
			depth++
		case 4:
			if depth == 0 {
				return 0, ErrUnexpectedEndOfGroupQuery
			}
			depth--
		case 5:
			iNdEx += 4
		default:
			return 0, fmt.Errorf("proto: illegal wireType %d", wireType)
		}
		if iNdEx < 0 {
			return 0, ErrInvalidLengthQuery
		}
		if depth == 0 {
			return iNdEx, nil
		}
	}
	return 0, io.ErrUnexpectedEOF
}

var (
	ErrInvalidLengthQuery        = fmt.Errorf("proto: negative length found during unmarshaling")
	ErrIntOverflowQuery          = fmt.Errorf("proto: integer overflow")
	ErrUnexpectedEndOfGroupQuery = fmt.Errorf("proto: unexpected end of group")
)
