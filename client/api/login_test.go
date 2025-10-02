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

func TestNewUserLoginHandler_Success(t *testing.T) {
	mockClient := new(mocks.MockSensitiveDataServiceClient)
	email := "test@example.com"
	password := "testPassword123"
	expectedToken := "test-access-token"
	expectedSalt := []byte("test-salt-12345678901234567890123456") // 32 байта для соли

	expectedResp := &sensitive.LoginUserResponse{
		AccessToken: expectedToken,
		Salt:        expectedSalt,
	}

	mockClient.On("LoginUser", mock.Anything, &sensitive.LoginUserRequest{
		Email:    email,
		Password: password,
	}).Return(expectedResp, nil)

	handler := NewUserLoginHandler(mockClient)

	token, cryptoKey, err := handler(context.Background(), email, password)

	// Assert
	assert.NoError(t, err)
	assert.Equal(t, expectedToken, token)
	assert.NotNil(t, cryptoKey)
	assert.NotEmpty(t, cryptoKey)
	mockClient.AssertExpectations(t)
}

func TestNewUserLoginHandler_LoginUserError(t *testing.T) {
	mockClient := new(mocks.MockSensitiveDataServiceClient)
	email := "test@example.com"
	password := "testPassword123"
	expectedError := errors.New("authentication failed")

	mockClient.On("LoginUser", mock.Anything, &sensitive.LoginUserRequest{
		Email:    email,
		Password: password,
	}).Return(nil, expectedError)

	handler := NewUserLoginHandler(mockClient)

	token, cryptoKey, err := handler(context.Background(), email, password)

	// Assert
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "could not register User")
	assert.Empty(t, token)
	assert.Nil(t, cryptoKey)
	mockClient.AssertExpectations(t)
}
