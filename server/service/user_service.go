package service

import (
	"context"
	"fmt"
	user "github.com/ruslanDantsov/password-manager/pkg/v1"
)

type UserService struct {
	user.UnimplementedAuthServiceServer
}

func NewUserService() *UserService {
	return new(UserService)
}

func (s *UserService) Register(ctx context.Context, req *user.RegisterRequest) (*user.RegisterResponse, error) {
	fmt.Println("Register User")
	return &user.RegisterResponse{}, nil
}

func (s *UserService) Login(ctx context.Context, req *user.LoginRequest) (*user.LoginResponse, error) {
	fmt.Println("Login User")
	return &user.LoginResponse{}, nil
}
func (s *UserService) RefreshToken(ctx context.Context, req *user.RefreshTokenRequest) (*user.RefreshTokenResponse, error) {
	fmt.Println("Refresh Token User")
	return &user.RefreshTokenResponse{}, nil
}
