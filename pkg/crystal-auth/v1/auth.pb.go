// Code generated by protoc-gen-go. DO NOT EDIT.
// versions:
// 	protoc-gen-go v1.31.0
// 	protoc        v3.19.6
// source: crystal-auth/v1/auth.proto

package crystal_auth

import (
	_ "github.com/grpc-ecosystem/grpc-gateway/v2/protoc-gen-openapiv2/options"
	_ "google.golang.org/genproto/googleapis/api/annotations"
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

type Empty struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields
}

func (x *Empty) Reset() {
	*x = Empty{}
	if protoimpl.UnsafeEnabled {
		mi := &file_crystal_auth_v1_auth_proto_msgTypes[0]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *Empty) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*Empty) ProtoMessage() {}

func (x *Empty) ProtoReflect() protoreflect.Message {
	mi := &file_crystal_auth_v1_auth_proto_msgTypes[0]
	if protoimpl.UnsafeEnabled && x != nil {
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
	return file_crystal_auth_v1_auth_proto_rawDescGZIP(), []int{0}
}

type UserInfo struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	Email       string `protobuf:"bytes,1,opt,name=email,proto3" json:"email,omitempty"`
	FirstName   string `protobuf:"bytes,2,opt,name=first_name,json=firstName,proto3" json:"first_name,omitempty"`
	LastName    string `protobuf:"bytes,3,opt,name=last_name,json=lastName,proto3" json:"last_name,omitempty"`
	Password    string `protobuf:"bytes,4,opt,name=password,proto3" json:"password,omitempty"`
	Role        int64  `protobuf:"varint,5,opt,name=role,proto3" json:"role,omitempty"`
	PhoneNumber string `protobuf:"bytes,6,opt,name=phone_number,json=phoneNumber,proto3" json:"phone_number,omitempty"`
}

func (x *UserInfo) Reset() {
	*x = UserInfo{}
	if protoimpl.UnsafeEnabled {
		mi := &file_crystal_auth_v1_auth_proto_msgTypes[1]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *UserInfo) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*UserInfo) ProtoMessage() {}

func (x *UserInfo) ProtoReflect() protoreflect.Message {
	mi := &file_crystal_auth_v1_auth_proto_msgTypes[1]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use UserInfo.ProtoReflect.Descriptor instead.
func (*UserInfo) Descriptor() ([]byte, []int) {
	return file_crystal_auth_v1_auth_proto_rawDescGZIP(), []int{1}
}

func (x *UserInfo) GetEmail() string {
	if x != nil {
		return x.Email
	}
	return ""
}

func (x *UserInfo) GetFirstName() string {
	if x != nil {
		return x.FirstName
	}
	return ""
}

func (x *UserInfo) GetLastName() string {
	if x != nil {
		return x.LastName
	}
	return ""
}

func (x *UserInfo) GetPassword() string {
	if x != nil {
		return x.Password
	}
	return ""
}

func (x *UserInfo) GetRole() int64 {
	if x != nil {
		return x.Role
	}
	return 0
}

func (x *UserInfo) GetPhoneNumber() string {
	if x != nil {
		return x.PhoneNumber
	}
	return ""
}

type JwtToken struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	Token string `protobuf:"bytes,1,opt,name=token,proto3" json:"token,omitempty"`
}

func (x *JwtToken) Reset() {
	*x = JwtToken{}
	if protoimpl.UnsafeEnabled {
		mi := &file_crystal_auth_v1_auth_proto_msgTypes[2]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *JwtToken) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*JwtToken) ProtoMessage() {}

func (x *JwtToken) ProtoReflect() protoreflect.Message {
	mi := &file_crystal_auth_v1_auth_proto_msgTypes[2]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use JwtToken.ProtoReflect.Descriptor instead.
func (*JwtToken) Descriptor() ([]byte, []int) {
	return file_crystal_auth_v1_auth_proto_rawDescGZIP(), []int{2}
}

func (x *JwtToken) GetToken() string {
	if x != nil {
		return x.Token
	}
	return ""
}

type AuthorizeInfo struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	Token        *JwtToken `protobuf:"bytes,1,opt,name=token,proto3" json:"token,omitempty"`
	ExpectedRole int64     `protobuf:"varint,2,opt,name=expectedRole,proto3" json:"expectedRole,omitempty"`
}

func (x *AuthorizeInfo) Reset() {
	*x = AuthorizeInfo{}
	if protoimpl.UnsafeEnabled {
		mi := &file_crystal_auth_v1_auth_proto_msgTypes[3]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *AuthorizeInfo) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*AuthorizeInfo) ProtoMessage() {}

func (x *AuthorizeInfo) ProtoReflect() protoreflect.Message {
	mi := &file_crystal_auth_v1_auth_proto_msgTypes[3]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use AuthorizeInfo.ProtoReflect.Descriptor instead.
func (*AuthorizeInfo) Descriptor() ([]byte, []int) {
	return file_crystal_auth_v1_auth_proto_rawDescGZIP(), []int{3}
}

func (x *AuthorizeInfo) GetToken() *JwtToken {
	if x != nil {
		return x.Token
	}
	return nil
}

func (x *AuthorizeInfo) GetExpectedRole() int64 {
	if x != nil {
		return x.ExpectedRole
	}
	return 0
}

type UserCredentials struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	Email    string `protobuf:"bytes,1,opt,name=email,proto3" json:"email,omitempty"`
	Password string `protobuf:"bytes,2,opt,name=password,proto3" json:"password,omitempty"`
}

func (x *UserCredentials) Reset() {
	*x = UserCredentials{}
	if protoimpl.UnsafeEnabled {
		mi := &file_crystal_auth_v1_auth_proto_msgTypes[4]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *UserCredentials) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*UserCredentials) ProtoMessage() {}

func (x *UserCredentials) ProtoReflect() protoreflect.Message {
	mi := &file_crystal_auth_v1_auth_proto_msgTypes[4]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use UserCredentials.ProtoReflect.Descriptor instead.
func (*UserCredentials) Descriptor() ([]byte, []int) {
	return file_crystal_auth_v1_auth_proto_rawDescGZIP(), []int{4}
}

func (x *UserCredentials) GetEmail() string {
	if x != nil {
		return x.Email
	}
	return ""
}

func (x *UserCredentials) GetPassword() string {
	if x != nil {
		return x.Password
	}
	return ""
}

type Access struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	Accessed bool `protobuf:"varint,1,opt,name=accessed,proto3" json:"accessed,omitempty"`
}

func (x *Access) Reset() {
	*x = Access{}
	if protoimpl.UnsafeEnabled {
		mi := &file_crystal_auth_v1_auth_proto_msgTypes[5]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *Access) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*Access) ProtoMessage() {}

func (x *Access) ProtoReflect() protoreflect.Message {
	mi := &file_crystal_auth_v1_auth_proto_msgTypes[5]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use Access.ProtoReflect.Descriptor instead.
func (*Access) Descriptor() ([]byte, []int) {
	return file_crystal_auth_v1_auth_proto_rawDescGZIP(), []int{5}
}

func (x *Access) GetAccessed() bool {
	if x != nil {
		return x.Accessed
	}
	return false
}

var File_crystal_auth_v1_auth_proto protoreflect.FileDescriptor

var file_crystal_auth_v1_auth_proto_rawDesc = []byte{
	0x0a, 0x1a, 0x63, 0x72, 0x79, 0x73, 0x74, 0x61, 0x6c, 0x2d, 0x61, 0x75, 0x74, 0x68, 0x2f, 0x76,
	0x31, 0x2f, 0x61, 0x75, 0x74, 0x68, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x12, 0x0f, 0x63, 0x72,
	0x79, 0x73, 0x74, 0x61, 0x6c, 0x5f, 0x61, 0x75, 0x74, 0x68, 0x2e, 0x76, 0x31, 0x1a, 0x1c, 0x67,
	0x6f, 0x6f, 0x67, 0x6c, 0x65, 0x2f, 0x61, 0x70, 0x69, 0x2f, 0x61, 0x6e, 0x6e, 0x6f, 0x74, 0x61,
	0x74, 0x69, 0x6f, 0x6e, 0x73, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x1a, 0x2e, 0x70, 0x72, 0x6f,
	0x74, 0x6f, 0x63, 0x2d, 0x67, 0x65, 0x6e, 0x2d, 0x6f, 0x70, 0x65, 0x6e, 0x61, 0x70, 0x69, 0x76,
	0x32, 0x2f, 0x6f, 0x70, 0x74, 0x69, 0x6f, 0x6e, 0x73, 0x2f, 0x61, 0x6e, 0x6e, 0x6f, 0x74, 0x61,
	0x74, 0x69, 0x6f, 0x6e, 0x73, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x22, 0x07, 0x0a, 0x05, 0x45,
	0x6d, 0x70, 0x74, 0x79, 0x22, 0xaf, 0x01, 0x0a, 0x08, 0x55, 0x73, 0x65, 0x72, 0x49, 0x6e, 0x66,
	0x6f, 0x12, 0x14, 0x0a, 0x05, 0x65, 0x6d, 0x61, 0x69, 0x6c, 0x18, 0x01, 0x20, 0x01, 0x28, 0x09,
	0x52, 0x05, 0x65, 0x6d, 0x61, 0x69, 0x6c, 0x12, 0x1d, 0x0a, 0x0a, 0x66, 0x69, 0x72, 0x73, 0x74,
	0x5f, 0x6e, 0x61, 0x6d, 0x65, 0x18, 0x02, 0x20, 0x01, 0x28, 0x09, 0x52, 0x09, 0x66, 0x69, 0x72,
	0x73, 0x74, 0x4e, 0x61, 0x6d, 0x65, 0x12, 0x1b, 0x0a, 0x09, 0x6c, 0x61, 0x73, 0x74, 0x5f, 0x6e,
	0x61, 0x6d, 0x65, 0x18, 0x03, 0x20, 0x01, 0x28, 0x09, 0x52, 0x08, 0x6c, 0x61, 0x73, 0x74, 0x4e,
	0x61, 0x6d, 0x65, 0x12, 0x1a, 0x0a, 0x08, 0x70, 0x61, 0x73, 0x73, 0x77, 0x6f, 0x72, 0x64, 0x18,
	0x04, 0x20, 0x01, 0x28, 0x09, 0x52, 0x08, 0x70, 0x61, 0x73, 0x73, 0x77, 0x6f, 0x72, 0x64, 0x12,
	0x12, 0x0a, 0x04, 0x72, 0x6f, 0x6c, 0x65, 0x18, 0x05, 0x20, 0x01, 0x28, 0x03, 0x52, 0x04, 0x72,
	0x6f, 0x6c, 0x65, 0x12, 0x21, 0x0a, 0x0c, 0x70, 0x68, 0x6f, 0x6e, 0x65, 0x5f, 0x6e, 0x75, 0x6d,
	0x62, 0x65, 0x72, 0x18, 0x06, 0x20, 0x01, 0x28, 0x09, 0x52, 0x0b, 0x70, 0x68, 0x6f, 0x6e, 0x65,
	0x4e, 0x75, 0x6d, 0x62, 0x65, 0x72, 0x22, 0x20, 0x0a, 0x08, 0x4a, 0x77, 0x74, 0x54, 0x6f, 0x6b,
	0x65, 0x6e, 0x12, 0x14, 0x0a, 0x05, 0x74, 0x6f, 0x6b, 0x65, 0x6e, 0x18, 0x01, 0x20, 0x01, 0x28,
	0x09, 0x52, 0x05, 0x74, 0x6f, 0x6b, 0x65, 0x6e, 0x22, 0x64, 0x0a, 0x0d, 0x41, 0x75, 0x74, 0x68,
	0x6f, 0x72, 0x69, 0x7a, 0x65, 0x49, 0x6e, 0x66, 0x6f, 0x12, 0x2f, 0x0a, 0x05, 0x74, 0x6f, 0x6b,
	0x65, 0x6e, 0x18, 0x01, 0x20, 0x01, 0x28, 0x0b, 0x32, 0x19, 0x2e, 0x63, 0x72, 0x79, 0x73, 0x74,
	0x61, 0x6c, 0x5f, 0x61, 0x75, 0x74, 0x68, 0x2e, 0x76, 0x31, 0x2e, 0x4a, 0x77, 0x74, 0x54, 0x6f,
	0x6b, 0x65, 0x6e, 0x52, 0x05, 0x74, 0x6f, 0x6b, 0x65, 0x6e, 0x12, 0x22, 0x0a, 0x0c, 0x65, 0x78,
	0x70, 0x65, 0x63, 0x74, 0x65, 0x64, 0x52, 0x6f, 0x6c, 0x65, 0x18, 0x02, 0x20, 0x01, 0x28, 0x03,
	0x52, 0x0c, 0x65, 0x78, 0x70, 0x65, 0x63, 0x74, 0x65, 0x64, 0x52, 0x6f, 0x6c, 0x65, 0x22, 0x43,
	0x0a, 0x0f, 0x55, 0x73, 0x65, 0x72, 0x43, 0x72, 0x65, 0x64, 0x65, 0x6e, 0x74, 0x69, 0x61, 0x6c,
	0x73, 0x12, 0x14, 0x0a, 0x05, 0x65, 0x6d, 0x61, 0x69, 0x6c, 0x18, 0x01, 0x20, 0x01, 0x28, 0x09,
	0x52, 0x05, 0x65, 0x6d, 0x61, 0x69, 0x6c, 0x12, 0x1a, 0x0a, 0x08, 0x70, 0x61, 0x73, 0x73, 0x77,
	0x6f, 0x72, 0x64, 0x18, 0x02, 0x20, 0x01, 0x28, 0x09, 0x52, 0x08, 0x70, 0x61, 0x73, 0x73, 0x77,
	0x6f, 0x72, 0x64, 0x22, 0x24, 0x0a, 0x06, 0x41, 0x63, 0x63, 0x65, 0x73, 0x73, 0x12, 0x1a, 0x0a,
	0x08, 0x61, 0x63, 0x63, 0x65, 0x73, 0x73, 0x65, 0x64, 0x18, 0x01, 0x20, 0x01, 0x28, 0x08, 0x52,
	0x08, 0x61, 0x63, 0x63, 0x65, 0x73, 0x73, 0x65, 0x64, 0x32, 0xf8, 0x02, 0x0a, 0x0b, 0x41, 0x75,
	0x74, 0x68, 0x53, 0x65, 0x72, 0x76, 0x69, 0x63, 0x65, 0x12, 0x59, 0x0a, 0x08, 0x52, 0x65, 0x67,
	0x69, 0x73, 0x74, 0x65, 0x72, 0x12, 0x19, 0x2e, 0x63, 0x72, 0x79, 0x73, 0x74, 0x61, 0x6c, 0x5f,
	0x61, 0x75, 0x74, 0x68, 0x2e, 0x76, 0x31, 0x2e, 0x55, 0x73, 0x65, 0x72, 0x49, 0x6e, 0x66, 0x6f,
	0x1a, 0x19, 0x2e, 0x63, 0x72, 0x79, 0x73, 0x74, 0x61, 0x6c, 0x5f, 0x61, 0x75, 0x74, 0x68, 0x2e,
	0x76, 0x31, 0x2e, 0x4a, 0x77, 0x74, 0x54, 0x6f, 0x6b, 0x65, 0x6e, 0x22, 0x17, 0x82, 0xd3, 0xe4,
	0x93, 0x02, 0x11, 0x3a, 0x01, 0x2a, 0x22, 0x0c, 0x2f, 0x76, 0x31, 0x2f, 0x72, 0x65, 0x67, 0x69,
	0x73, 0x74, 0x65, 0x72, 0x12, 0x5a, 0x0a, 0x05, 0x4c, 0x6f, 0x67, 0x69, 0x6e, 0x12, 0x20, 0x2e,
	0x63, 0x72, 0x79, 0x73, 0x74, 0x61, 0x6c, 0x5f, 0x61, 0x75, 0x74, 0x68, 0x2e, 0x76, 0x31, 0x2e,
	0x55, 0x73, 0x65, 0x72, 0x43, 0x72, 0x65, 0x64, 0x65, 0x6e, 0x74, 0x69, 0x61, 0x6c, 0x73, 0x1a,
	0x19, 0x2e, 0x63, 0x72, 0x79, 0x73, 0x74, 0x61, 0x6c, 0x5f, 0x61, 0x75, 0x74, 0x68, 0x2e, 0x76,
	0x31, 0x2e, 0x4a, 0x77, 0x74, 0x54, 0x6f, 0x6b, 0x65, 0x6e, 0x22, 0x14, 0x82, 0xd3, 0xe4, 0x93,
	0x02, 0x0e, 0x3a, 0x01, 0x2a, 0x22, 0x09, 0x2f, 0x76, 0x31, 0x2f, 0x6c, 0x6f, 0x67, 0x69, 0x6e,
	0x12, 0x5e, 0x0a, 0x09, 0x41, 0x75, 0x74, 0x68, 0x6f, 0x72, 0x69, 0x7a, 0x65, 0x12, 0x1e, 0x2e,
	0x63, 0x72, 0x79, 0x73, 0x74, 0x61, 0x6c, 0x5f, 0x61, 0x75, 0x74, 0x68, 0x2e, 0x76, 0x31, 0x2e,
	0x41, 0x75, 0x74, 0x68, 0x6f, 0x72, 0x69, 0x7a, 0x65, 0x49, 0x6e, 0x66, 0x6f, 0x1a, 0x17, 0x2e,
	0x63, 0x72, 0x79, 0x73, 0x74, 0x61, 0x6c, 0x5f, 0x61, 0x75, 0x74, 0x68, 0x2e, 0x76, 0x31, 0x2e,
	0x41, 0x63, 0x63, 0x65, 0x73, 0x73, 0x22, 0x18, 0x82, 0xd3, 0xe4, 0x93, 0x02, 0x12, 0x3a, 0x01,
	0x2a, 0x22, 0x0d, 0x2f, 0x76, 0x31, 0x2f, 0x61, 0x75, 0x74, 0x68, 0x6f, 0x72, 0x69, 0x7a, 0x65,
	0x12, 0x52, 0x0a, 0x06, 0x4c, 0x6f, 0x67, 0x6f, 0x75, 0x74, 0x12, 0x19, 0x2e, 0x63, 0x72, 0x79,
	0x73, 0x74, 0x61, 0x6c, 0x5f, 0x61, 0x75, 0x74, 0x68, 0x2e, 0x76, 0x31, 0x2e, 0x4a, 0x77, 0x74,
	0x54, 0x6f, 0x6b, 0x65, 0x6e, 0x1a, 0x16, 0x2e, 0x63, 0x72, 0x79, 0x73, 0x74, 0x61, 0x6c, 0x5f,
	0x61, 0x75, 0x74, 0x68, 0x2e, 0x76, 0x31, 0x2e, 0x45, 0x6d, 0x70, 0x74, 0x79, 0x22, 0x15, 0x82,
	0xd3, 0xe4, 0x93, 0x02, 0x0f, 0x3a, 0x01, 0x2a, 0x22, 0x0a, 0x2f, 0x76, 0x31, 0x2f, 0x6c, 0x6f,
	0x67, 0x6f, 0x75, 0x74, 0x42, 0x86, 0x01, 0x92, 0x41, 0x3e, 0x12, 0x14, 0x0a, 0x0c, 0x41, 0x75,
	0x74, 0x68, 0x20, 0x53, 0x65, 0x72, 0x76, 0x69, 0x63, 0x65, 0x32, 0x04, 0x76, 0x31, 0x2e, 0x30,
	0x2a, 0x02, 0x01, 0x02, 0x32, 0x10, 0x61, 0x70, 0x70, 0x6c, 0x69, 0x63, 0x61, 0x74, 0x69, 0x6f,
	0x6e, 0x2f, 0x6a, 0x73, 0x6f, 0x6e, 0x3a, 0x10, 0x61, 0x70, 0x70, 0x6c, 0x69, 0x63, 0x61, 0x74,
	0x69, 0x6f, 0x6e, 0x2f, 0x6a, 0x73, 0x6f, 0x6e, 0x5a, 0x43, 0x67, 0x69, 0x74, 0x68, 0x75, 0x62,
	0x2e, 0x63, 0x6f, 0x6d, 0x2f, 0x44, 0x6d, 0x69, 0x74, 0x72, 0x69, 0x79, 0x2d, 0x4d, 0x31, 0x33,
	0x31, 0x39, 0x2f, 0x63, 0x72, 0x79, 0x73, 0x74, 0x61, 0x6c, 0x2d, 0x61, 0x75, 0x74, 0x68, 0x2f,
	0x70, 0x6b, 0x67, 0x2f, 0x63, 0x72, 0x79, 0x73, 0x74, 0x61, 0x6c, 0x5f, 0x61, 0x75, 0x74, 0x68,
	0x3b, 0x63, 0x72, 0x79, 0x73, 0x74, 0x61, 0x6c, 0x5f, 0x61, 0x75, 0x74, 0x68, 0x62, 0x06, 0x70,
	0x72, 0x6f, 0x74, 0x6f, 0x33,
}

var (
	file_crystal_auth_v1_auth_proto_rawDescOnce sync.Once
	file_crystal_auth_v1_auth_proto_rawDescData = file_crystal_auth_v1_auth_proto_rawDesc
)

func file_crystal_auth_v1_auth_proto_rawDescGZIP() []byte {
	file_crystal_auth_v1_auth_proto_rawDescOnce.Do(func() {
		file_crystal_auth_v1_auth_proto_rawDescData = protoimpl.X.CompressGZIP(file_crystal_auth_v1_auth_proto_rawDescData)
	})
	return file_crystal_auth_v1_auth_proto_rawDescData
}

var file_crystal_auth_v1_auth_proto_msgTypes = make([]protoimpl.MessageInfo, 6)
var file_crystal_auth_v1_auth_proto_goTypes = []interface{}{
	(*Empty)(nil),           // 0: crystal_auth.v1.Empty
	(*UserInfo)(nil),        // 1: crystal_auth.v1.UserInfo
	(*JwtToken)(nil),        // 2: crystal_auth.v1.JwtToken
	(*AuthorizeInfo)(nil),   // 3: crystal_auth.v1.AuthorizeInfo
	(*UserCredentials)(nil), // 4: crystal_auth.v1.UserCredentials
	(*Access)(nil),          // 5: crystal_auth.v1.Access
}
var file_crystal_auth_v1_auth_proto_depIdxs = []int32{
	2, // 0: crystal_auth.v1.AuthorizeInfo.token:type_name -> crystal_auth.v1.JwtToken
	1, // 1: crystal_auth.v1.AuthService.Register:input_type -> crystal_auth.v1.UserInfo
	4, // 2: crystal_auth.v1.AuthService.Login:input_type -> crystal_auth.v1.UserCredentials
	3, // 3: crystal_auth.v1.AuthService.Authorize:input_type -> crystal_auth.v1.AuthorizeInfo
	2, // 4: crystal_auth.v1.AuthService.Logout:input_type -> crystal_auth.v1.JwtToken
	2, // 5: crystal_auth.v1.AuthService.Register:output_type -> crystal_auth.v1.JwtToken
	2, // 6: crystal_auth.v1.AuthService.Login:output_type -> crystal_auth.v1.JwtToken
	5, // 7: crystal_auth.v1.AuthService.Authorize:output_type -> crystal_auth.v1.Access
	0, // 8: crystal_auth.v1.AuthService.Logout:output_type -> crystal_auth.v1.Empty
	5, // [5:9] is the sub-list for method output_type
	1, // [1:5] is the sub-list for method input_type
	1, // [1:1] is the sub-list for extension type_name
	1, // [1:1] is the sub-list for extension extendee
	0, // [0:1] is the sub-list for field type_name
}

func init() { file_crystal_auth_v1_auth_proto_init() }
func file_crystal_auth_v1_auth_proto_init() {
	if File_crystal_auth_v1_auth_proto != nil {
		return
	}
	if !protoimpl.UnsafeEnabled {
		file_crystal_auth_v1_auth_proto_msgTypes[0].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*Empty); i {
			case 0:
				return &v.state
			case 1:
				return &v.sizeCache
			case 2:
				return &v.unknownFields
			default:
				return nil
			}
		}
		file_crystal_auth_v1_auth_proto_msgTypes[1].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*UserInfo); i {
			case 0:
				return &v.state
			case 1:
				return &v.sizeCache
			case 2:
				return &v.unknownFields
			default:
				return nil
			}
		}
		file_crystal_auth_v1_auth_proto_msgTypes[2].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*JwtToken); i {
			case 0:
				return &v.state
			case 1:
				return &v.sizeCache
			case 2:
				return &v.unknownFields
			default:
				return nil
			}
		}
		file_crystal_auth_v1_auth_proto_msgTypes[3].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*AuthorizeInfo); i {
			case 0:
				return &v.state
			case 1:
				return &v.sizeCache
			case 2:
				return &v.unknownFields
			default:
				return nil
			}
		}
		file_crystal_auth_v1_auth_proto_msgTypes[4].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*UserCredentials); i {
			case 0:
				return &v.state
			case 1:
				return &v.sizeCache
			case 2:
				return &v.unknownFields
			default:
				return nil
			}
		}
		file_crystal_auth_v1_auth_proto_msgTypes[5].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*Access); i {
			case 0:
				return &v.state
			case 1:
				return &v.sizeCache
			case 2:
				return &v.unknownFields
			default:
				return nil
			}
		}
	}
	type x struct{}
	out := protoimpl.TypeBuilder{
		File: protoimpl.DescBuilder{
			GoPackagePath: reflect.TypeOf(x{}).PkgPath(),
			RawDescriptor: file_crystal_auth_v1_auth_proto_rawDesc,
			NumEnums:      0,
			NumMessages:   6,
			NumExtensions: 0,
			NumServices:   1,
		},
		GoTypes:           file_crystal_auth_v1_auth_proto_goTypes,
		DependencyIndexes: file_crystal_auth_v1_auth_proto_depIdxs,
		MessageInfos:      file_crystal_auth_v1_auth_proto_msgTypes,
	}.Build()
	File_crystal_auth_v1_auth_proto = out.File
	file_crystal_auth_v1_auth_proto_rawDesc = nil
	file_crystal_auth_v1_auth_proto_goTypes = nil
	file_crystal_auth_v1_auth_proto_depIdxs = nil
}
