package api

import (
	"context"
	"github.com/ruslanDantsov/password-manager/pkg/crypto"
	sensitive "github.com/ruslanDantsov/password-manager/pkg/v1"
)

func NewGetCardListHandler(sensitiveDataClient sensitive.SensitiveDataServiceClient) func(ctx context.Context, authToken string, cryptoKey []byte) ([]*sensitive.CardData, error) {
	return func(ctx context.Context, authToken string, cryptoKey []byte) ([]*sensitive.CardData, error) {
		ctxWithToken := AddAuthToken(ctx, authToken)
		resp, err := sensitiveDataClient.GetCardDataList(ctxWithToken, &sensitive.GetCardDataListRequest{})
		if err != nil {
			return nil, err
		}

		for i, card := range resp.CardData {
			decryptedCardNumber, err := crypto.Decrypt(card.CardNumberEncrypted, cryptoKey)
			if err != nil {
				continue
			}
			decryptedCvv, err := crypto.Decrypt(card.CvvEncrypted, cryptoKey)
			if err != nil {
				continue
			}
			resp.CardData[i].CardNumberEncrypted = decryptedCardNumber
			resp.CardData[i].CvvEncrypted = decryptedCvv
		}

		return resp.CardData, nil
	}
}
