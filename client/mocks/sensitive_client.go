package mocks

import (
	"context"
	sensitive "github.com/ruslanDantsov/password-manager/pkg/v1"
	"github.com/stretchr/testify/mock"
	"google.golang.org/grpc"
)

type MockSensitiveDataServiceClient struct {
	mock.Mock
}

func (m *MockSensitiveDataServiceClient) RegisterUser(ctx context.Context, req *sensitive.RegisterUserRequest, opts ...grpc.CallOption) (*sensitive.RegisterUserResponse, error) {
	args := m.Called(ctx, req)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*sensitive.RegisterUserResponse), args.Error(1)
}

func (m *MockSensitiveDataServiceClient) LoginUser(ctx context.Context, req *sensitive.LoginUserRequest, opts ...grpc.CallOption) (*sensitive.LoginUserResponse, error) {
	args := m.Called(ctx, req)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*sensitive.LoginUserResponse), args.Error(1)
}

func (m *MockSensitiveDataServiceClient) AddCredentialData(ctx context.Context, req *sensitive.AddCredentialDataRequest, opts ...grpc.CallOption) (*sensitive.AddCredentialDataResponse, error) {
	args := m.Called(ctx, req)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*sensitive.AddCredentialDataResponse), args.Error(1)
}

func (m *MockSensitiveDataServiceClient) GetCredentialDataList(ctx context.Context, req *sensitive.GetCredentialDataListRequest, opts ...grpc.CallOption) (*sensitive.GetCredentialDataListResponse, error) {
	args := m.Called(ctx, req)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*sensitive.GetCredentialDataListResponse), args.Error(1)
}

func (m *MockSensitiveDataServiceClient) AddTextData(ctx context.Context, req *sensitive.AddTextDataRequest, opts ...grpc.CallOption) (*sensitive.AddTextDataResponse, error) {
	args := m.Called(ctx, req)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*sensitive.AddTextDataResponse), args.Error(1)
}

func (m *MockSensitiveDataServiceClient) GetTextDataList(ctx context.Context, req *sensitive.GetTextDataListRequest, opts ...grpc.CallOption) (*sensitive.GetTextDataListResponse, error) {
	args := m.Called(ctx, req)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*sensitive.GetTextDataListResponse), args.Error(1)
}

func (m *MockSensitiveDataServiceClient) AddCardData(ctx context.Context, req *sensitive.AddCardDataRequest, opts ...grpc.CallOption) (*sensitive.AddCardDataResponse, error) {
	args := m.Called(ctx, req)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*sensitive.AddCardDataResponse), args.Error(1)
}

func (m *MockSensitiveDataServiceClient) GetCardDataList(ctx context.Context, req *sensitive.GetCardDataListRequest, opts ...grpc.CallOption) (*sensitive.GetCardDataListResponse, error) {
	args := m.Called(ctx, req)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*sensitive.GetCardDataListResponse), args.Error(1)
}

var _ sensitive.SensitiveDataServiceClient = (*MockSensitiveDataServiceClient)(nil)
