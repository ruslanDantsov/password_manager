package api

import (
	"context"
	"github.com/ruslanDantsov/password-manager/pkg/crypto"
	sensitive "github.com/ruslanDantsov/password-manager/pkg/v1"
)

func NewAddCardHandler(sensitiveDataClient sensitive.SensitiveDataServiceClient) func(
	ctx context.Context,
	serviceName string,
	cardholderName string,
	cardNumberEncrypted string,
	expiryMonth int32,
	expiryYear int32,
	cvvEncrypted string,
	authToken string,
	cryptoKey []byte) error {
	return func(
		ctx context.Context,
		serviceName string,
		cardholderName string,
		cardNumberEncrypted string,
		expiryMonth int32,
		expiryYear int32,
		cvvEncrypted string,
		authToken string,
		cryptoKey []byte) error {
		cryptoCardNumber, err := crypto.Encrypt([]byte(cardNumberEncrypted), cryptoKey)
		if err != nil {
			return err
		}
		cryptoCvv, err := crypto.Encrypt([]byte(cvvEncrypted), cryptoKey)
		if err != nil {
			return err
		}

		ctxWithToken := AddAuthToken(ctx, authToken)
		_, err = sensitiveDataClient.AddCardData(ctxWithToken, &sensitive.AddCardDataRequest{
			ServiceName:         serviceName,
			CardholderName:      cardholderName,
			CardNumberEncrypted: cryptoCardNumber,
			ExpiryMonth:         expiryMonth,
			ExpiryYear:          expiryYear,
			CvvEncrypted:        cryptoCvv,
		})

		return err
	}
}
