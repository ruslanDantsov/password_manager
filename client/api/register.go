package api

import (
	"context"
	"fmt"
	sensitive "github.com/ruslanDantsov/password-manager/pkg/v1"
)

func NewUserRegisterHandler(sensitiveDataClient sensitive.SensitiveDataServiceClient) func(ctx context.Context, email, password, name string) error {
	return func(ctx context.Context, email, password, displayName string) error {
		_, err := sensitiveDataClient.RegisterUser(context.Background(), &sensitive.RegisterUserRequest{
			Email:       email,
			Password:    password,
			DisplayName: displayName,
		})

		if err != nil {
			return fmt.Errorf("could not register User: %w", err)
		}
		return nil
	}
}
