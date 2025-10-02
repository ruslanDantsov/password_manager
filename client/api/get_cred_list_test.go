package api

import (
	"context"
	"errors"
	"github.com/ruslanDantsov/password-manager/client/mocks"
	"github.com/ruslanDantsov/password-manager/pkg/crypto"
	sensitive "github.com/ruslanDantsov/password-manager/pkg/v1"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"testing"
)

func TestNewGetCredListHandler_Success(t *testing.T) {
	// Arrange
	mockClient := new(mocks.MockSensitiveDataServiceClient)
	authToken := "test-auth-token"
	password := "mySecretPassword"
	cryptoKey := []byte("12345678901234567890123456789012")

	// Шифруем пароль для теста
	encryptedPass, err := crypto.Encrypt([]byte(password), cryptoKey)
	assert.NoError(t, err)

	expectedCredentials := []*sensitive.CredentialData{
		{
			ServiceName: "github.com",
			Login:       "user@example.com",
			Password:    encryptedPass,
		},
		{
			ServiceName: "gitlab.com",
			Login:       "admin",
			Password:    encryptedPass,
		},
	}

	mockResponse := &sensitive.GetCredentialDataListResponse{
		CredentialData: expectedCredentials,
	}

	mockClient.On("GetCredentialDataList", mock.Anything, &sensitive.GetCredentialDataListRequest{}).
		Return(mockResponse, nil)

	handler := NewGetCredListHandler(mockClient)

	// Act
	credentials, err := handler(context.Background(), authToken, cryptoKey)

	// Assert
	assert.NoError(t, err)
	assert.NotNil(t, credentials)
	assert.Len(t, credentials, 2)

	assert.Equal(t, "github.com", credentials[0].ServiceName)
	assert.Equal(t, "user@example.com", credentials[0].Login)
	assert.Equal(t, []byte(password), credentials[0].Password)

	assert.Equal(t, "gitlab.com", credentials[1].ServiceName)
	assert.Equal(t, "admin", credentials[1].Login)
	assert.Equal(t, []byte(password), credentials[1].Password)

	mockClient.AssertExpectations(t)
}

func TestNewGetCredListHandler_ClientError(t *testing.T) {
	// Arrange
	mockClient := new(mocks.MockSensitiveDataServiceClient)
	authToken := "test-auth-token"
	cryptoKey := []byte("12345678901234567890123456789012")
	expectedError := errors.New("unauthorized")

	mockClient.On("GetCredentialDataList", mock.Anything, &sensitive.GetCredentialDataListRequest{}).
		Return(nil, expectedError)

	handler := NewGetCredListHandler(mockClient)

	// Act
	credentials, err := handler(context.Background(), authToken, cryptoKey)

	// Assert
	assert.Error(t, err)
	assert.Equal(t, expectedError, err)
	assert.Nil(t, credentials)

	mockClient.AssertExpectations(t)
}
