package api

import (
	"context"
	"github.com/ruslanDantsov/password-manager/pkg/crypto"
	sensitive "github.com/ruslanDantsov/password-manager/pkg/v1"
)

func NewAddNoteHandler(sensitiveDataClient sensitive.SensitiveDataServiceClient) func(ctx context.Context, serviceName, note, authToken string, cryptoKey []byte) error {
	return func(ctx context.Context, serviceName, note, authToken string, cryptoKey []byte) error {
		cryptoNote, err := crypto.Encrypt([]byte(note), cryptoKey)
		if err != nil {
			return err
		}

		ctxWithToken := AddAuthToken(ctx, authToken)
		_, err = sensitiveDataClient.AddTextData(ctxWithToken, &sensitive.AddTextDataRequest{
			ServiceName: serviceName,
			Data:        cryptoNote,
		})

		return err
	}
}
