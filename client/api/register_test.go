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

func TestNewUserRegisterHandler_Success(t *testing.T) {
	// Arrange
	mockClient := new(mocks.MockSensitiveDataServiceClient)
	email := "test@example.com"
	password := "securePassword123"
	displayName := "Test User"

	expectedResp := &sensitive.RegisterUserResponse{
		UserId: 12345,
	}

	mockClient.On("RegisterUser", mock.Anything, &sensitive.RegisterUserRequest{
		Email:       email,
		Password:    password,
		DisplayName: displayName,
	}).Return(expectedResp, nil)

	handler := NewUserRegisterHandler(mockClient)

	// Act
	err := handler(context.Background(), email, password, displayName)

	// Assert
	assert.NoError(t, err)
	mockClient.AssertExpectations(t)
}

func TestNewUserRegisterHandler_Error(t *testing.T) {
	// Arrange
	mockClient := new(mocks.MockSensitiveDataServiceClient)
	email := "test@example.com"
	password := "securePassword123"
	displayName := "Test User"
	expectedError := errors.New("user already exists")

	mockClient.On("RegisterUser", mock.Anything, &sensitive.RegisterUserRequest{
		Email:       email,
		Password:    password,
		DisplayName: displayName,
	}).Return(nil, expectedError)

	handler := NewUserRegisterHandler(mockClient)

	// Act
	err := handler(context.Background(), email, password, displayName)

	// Assert
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "could not register User")
	assert.Contains(t, err.Error(), "user already exists")
	mockClient.AssertExpectations(t)
}
