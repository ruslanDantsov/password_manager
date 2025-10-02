package api

import (
	"context"
	"errors"
	"github.com/ruslanDantsov/password-manager/client/mocks"
	sensitive "github.com/ruslanDantsov/password-manager/pkg/v1"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"testing"
)

func TestNewAddCredHandler_Success(t *testing.T) {
	// Arrange
	mockClient := new(mocks.MockSensitiveDataServiceClient)
	serviceName := "github.com"
	login := "testuser"
	password := "testPassword123"
	authToken := "test-auth-token"

	cryptoKey := []byte("12345678901234567890123456789012")

	expectedResponse := &sensitive.AddCredentialDataResponse{
		SecretDataId: 123,
	}

	mockClient.On("AddCredentialData",
		mock.MatchedBy(func(ctx context.Context) bool {
			return ctx != nil
		}),
		mock.MatchedBy(func(req *sensitive.AddCredentialDataRequest) bool {
			if req.ServiceName != serviceName {
				return false
			}
			if req.Login != login {
				return false
			}
			if len(req.Password) == 0 || string(req.Password) == password {
				return false
			}
			return true
		}),
	).Return(expectedResponse, nil)

	handler := NewAddCredHandler(mockClient)

	// Act
	err := handler(context.Background(), serviceName, login, password, authToken, cryptoKey)

	// Assert
	assert.NoError(t, err)
	mockClient.AssertExpectations(t)
}

func TestNewAddCredHandler_AddCredentialDataError(t *testing.T) {
	// Arrange
	mockClient := new(mocks.MockSensitiveDataServiceClient)
	serviceName := "github.com"
	login := "testuser"
	password := "testPassword123"
	authToken := "test-auth-token"

	cryptoKey := []byte("12345678901234567890123456789012")

	expectedError := errors.New("failed to add credential data")

	mockClient.On("AddCredentialData",
		mock.Anything,
		mock.AnythingOfType("*sensitive.AddCredentialDataRequest"),
	).Return(nil, expectedError)

	handler := NewAddCredHandler(mockClient)

	// Act
	err := handler(context.Background(), serviceName, login, password, authToken, cryptoKey)

	// Assert
	assert.Error(t, err)
	assert.Equal(t, expectedError, err)
	mockClient.AssertExpectations(t)
}
