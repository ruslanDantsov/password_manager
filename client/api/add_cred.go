package api

import (
	"context"
	"github.com/ruslanDantsov/password-manager/pkg/crypto"
	sensitive "github.com/ruslanDantsov/password-manager/pkg/v1"
	"google.golang.org/grpc/metadata"
)

func NewAddCredHandler(sensitiveDataClient sensitive.SensitiveDataServiceClient) func(ctx context.Context, serviceName, login, password, authToken string, cryptoKey []byte) error {
	return func(ctx context.Context, serviceName, login, password, authToken string, cryptoKey []byte) error {
		cryptoPassword, err := crypto.Encrypt([]byte(password), cryptoKey)
		if err != nil {
			return err
		}

		ctxWithToken := AddAuthToken(ctx, authToken)
		_, err = sensitiveDataClient.AddCredentialData(ctxWithToken, &sensitive.AddCredentialDataRequest{
			ServiceName: serviceName,
			Login:       login,
			Password:    cryptoPassword,
		})

		return err
	}
}

func AddAuthToken(ctx context.Context, token string) context.Context {
	return metadata.AppendToOutgoingContext(ctx, "authorization", "Bearer "+token)
}
