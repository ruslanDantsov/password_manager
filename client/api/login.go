package api

import (
	"context"
	"fmt"
	"github.com/ruslanDantsov/password-manager/pkg/crypto"
	sensitive "github.com/ruslanDantsov/password-manager/pkg/v1"
)

func NewUserLoginHandler(sensitiveDataClient sensitive.SensitiveDataServiceClient) func(ctx context.Context, email, password string) (string, []byte, error) {
	return func(ctx context.Context, email, password string) (string, []byte, error) {
		resp, err := sensitiveDataClient.LoginUser(context.Background(), &sensitive.LoginUserRequest{
			Email:    email,
			Password: password,
		})

		if err != nil {
			return "", nil, fmt.Errorf("could not register User: %w", err)
		}

		cryptoKey, err := crypto.DeriveKDFKey([]byte(password), resp.Salt)
		if err != nil {
			return "", nil, fmt.Errorf("could not get crypto key: %w", err)
		}

		return resp.AccessToken, cryptoKey, nil
	}
}
