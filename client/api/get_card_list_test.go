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

func TestNewGetCardListHandler_Success(t *testing.T) {
	// Arrange
	mockClient := new(mocks.MockSensitiveDataServiceClient)
	authToken := "test-auth-token"

	cryptoKey := []byte("12345678901234567890123456789012")

	encryptedCardNumber := []byte("encrypted-card-number-data-here")
	encryptedCvv := []byte("encrypted-cvv-data")

	expectedResp := &sensitive.GetCardDataListResponse{
		CardData: []*sensitive.CardData{
			{
				ServiceName:         "Test Bank",
				CardholderName:      "John Doe",
				CardNumberEncrypted: encryptedCardNumber,
				ExpiryMonth:         12,
				ExpiryYear:          2025,
				CvvEncrypted:        encryptedCvv,
			},
		},
	}

	mockClient.On("GetCardDataList", mock.Anything, &sensitive.GetCardDataListRequest{}).
		Return(expectedResp, nil)

	handler := NewGetCardListHandler(mockClient)

	// Act
	cards, err := handler(context.Background(), authToken, cryptoKey)

	// Assert
	assert.NoError(t, err)
	assert.NotNil(t, cards)
	assert.Len(t, cards, 1)
	assert.Equal(t, "Test Bank", cards[0].ServiceName)
	assert.Equal(t, "John Doe", cards[0].CardholderName)
	assert.Equal(t, int32(12), cards[0].ExpiryMonth)
	assert.Equal(t, int32(2025), cards[0].ExpiryYear)
	assert.Equal(t, encryptedCardNumber, cards[0].CardNumberEncrypted)
	assert.Equal(t, encryptedCvv, cards[0].CvvEncrypted)
	mockClient.AssertExpectations(t)
}

func TestNewGetCardListHandler_ClientError(t *testing.T) {
	// Arrange
	mockClient := new(mocks.MockSensitiveDataServiceClient)
	authToken := "test-auth-token"
	cryptoKey := []byte("12345678901234567890123456789012")

	expectedError := errors.New("failed to fetch card data")

	mockClient.On("GetCardDataList", mock.Anything, &sensitive.GetCardDataListRequest{}).
		Return(nil, expectedError)

	handler := NewGetCardListHandler(mockClient)

	// Act
	cards, err := handler(context.Background(), authToken, cryptoKey)

	// Assert
	assert.Error(t, err)
	assert.Nil(t, cards)
	assert.Equal(t, expectedError, err)
	mockClient.AssertExpectations(t)
}
