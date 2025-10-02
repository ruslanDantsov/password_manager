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

func TestNewAddCardHandler_Success(t *testing.T) {
	// Arrange
	mockClient := new(mocks.MockSensitiveDataServiceClient)

	serviceName := "My Bank"
	cardholderName := "John Doe"
	cardNumber := "4111111111111111"
	expiryMonth := int32(12)
	expiryYear := int32(2025)
	cvv := "123"
	authToken := "test-token"
	cryptoKey := []byte("12345678901234567890123456789012")

	expectedResp := &sensitive.AddCardDataResponse{
		SecretDataId: 123,
	}

	// Настраиваем мок - ожидаем вызов с любыми зашифрованными данными
	mockClient.On("AddCardData", mock.Anything, mock.MatchedBy(func(req *sensitive.AddCardDataRequest) bool {
		return req.ServiceName == serviceName &&
			req.CardholderName == cardholderName &&
			req.ExpiryMonth == expiryMonth &&
			req.ExpiryYear == expiryYear &&
			len(req.CardNumberEncrypted) > 0 &&
			len(req.CvvEncrypted) > 0
	})).Return(expectedResp, nil)

	handler := NewAddCardHandler(mockClient)

	// Act
	err := handler(
		context.Background(),
		serviceName,
		cardholderName,
		cardNumber,
		expiryMonth,
		expiryYear,
		cvv,
		authToken,
		cryptoKey,
	)

	// Assert
	assert.NoError(t, err)
	mockClient.AssertExpectations(t)
}

func TestNewAddCardHandler_AddCardDataError(t *testing.T) {
	// Arrange
	mockClient := new(mocks.MockSensitiveDataServiceClient)

	serviceName := "My Bank"
	cardholderName := "John Doe"
	cardNumber := "4111111111111111"
	expiryMonth := int32(12)
	expiryYear := int32(2025)
	cvv := "123"
	authToken := "test-token"
	cryptoKey := []byte("12345678901234567890123456789012")

	expectedError := errors.New("failed to save card data")

	// Настраиваем мок - возвращаем ошибку
	mockClient.On("AddCardData", mock.Anything, mock.Anything).Return(nil, expectedError)

	handler := NewAddCardHandler(mockClient)

	// Act
	err := handler(
		context.Background(),
		serviceName,
		cardholderName,
		cardNumber,
		expiryMonth,
		expiryYear,
		cvv,
		authToken,
		cryptoKey,
	)

	// Assert
	assert.Error(t, err)
	assert.Equal(t, expectedError, err)
	mockClient.AssertExpectations(t)
}
