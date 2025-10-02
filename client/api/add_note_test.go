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

func TestNewAddNoteHandler_Success(t *testing.T) {
	// Arrange
	mockClient := new(mocks.MockSensitiveDataServiceClient)
	serviceName := "MyService"
	note := "This is a secret note"
	authToken := "test-auth-token"
	cryptoKey := []byte("12345678901234567890123456789012")

	expectedResponse := &sensitive.AddTextDataResponse{
		SecretDataId: 123,
	}

	// Ожидаем вызов AddTextData с любым контекстом и запросом
	mockClient.On("AddTextData", mock.Anything, mock.MatchedBy(func(req *sensitive.AddTextDataRequest) bool {
		// Проверяем, что service_name совпадает
		if req.ServiceName != serviceName {
			return false
		}
		// Проверяем, что данные зашифрованы (не пустые и не равны исходной заметке)
		if len(req.Data) == 0 || string(req.Data) == note {
			return false
		}
		return true
	})).Return(expectedResponse, nil)

	handler := NewAddNoteHandler(mockClient)

	// Act
	err := handler(context.Background(), serviceName, note, authToken, cryptoKey)

	// Assert
	assert.NoError(t, err)
	mockClient.AssertExpectations(t)
}

func TestNewAddNoteHandler_EncryptionError(t *testing.T) {
	// Arrange
	mockClient := new(mocks.MockSensitiveDataServiceClient)
	serviceName := "MyService"
	note := "This is a secret note"
	authToken := "test-auth-token"
	invalidCryptoKey := []byte("too-short")

	handler := NewAddNoteHandler(mockClient)

	// Act
	err := handler(context.Background(), serviceName, note, authToken, invalidCryptoKey)

	// Assert
	assert.Error(t, err)

	mockClient.AssertNotCalled(t, "AddTextData")
}

func TestNewAddNoteHandler_AddTextDataError(t *testing.T) {
	// Arrange
	mockClient := new(mocks.MockSensitiveDataServiceClient)
	serviceName := "MyService"
	note := "This is a secret note"
	authToken := "test-auth-token"
	cryptoKey := []byte("12345678901234567890123456789012")
	expectedError := errors.New("failed to add text data")

	mockClient.On("AddTextData", mock.Anything, mock.Anything).Return(nil, expectedError)

	handler := NewAddNoteHandler(mockClient)

	// Act
	err := handler(context.Background(), serviceName, note, authToken, cryptoKey)

	// Assert
	assert.Error(t, err)
	assert.Equal(t, expectedError, err)
	mockClient.AssertExpectations(t)
}
