package api

import (
	"context"
	"github.com/ruslanDantsov/password-manager/pkg/crypto"
	sensitive "github.com/ruslanDantsov/password-manager/pkg/v1"
)

func NewGetCredListHandler(sensitiveDataClient sensitive.SensitiveDataServiceClient) func(ctx context.Context, authToken string, cryptoKey []byte) ([]*sensitive.CredentialData, error) {
	return func(ctx context.Context, authToken string, cryptoKey []byte) ([]*sensitive.CredentialData, error) {
		ctxWithToken := AddAuthToken(ctx, authToken)
		resp, err := sensitiveDataClient.GetCredentialDataList(ctxWithToken, &sensitive.GetCredentialDataListRequest{})
		if err != nil {
			return nil, err
		}

		for i, cred := range resp.CredentialData {
			decryptedPass, err := crypto.Decrypt(cred.Password, cryptoKey)
			if err != nil {
				continue
			}
			resp.CredentialData[i].Password = decryptedPass
		}

		return resp.CredentialData, nil
	}
}
