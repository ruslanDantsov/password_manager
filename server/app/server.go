package app

import (
	"context"
	"fmt"
	"github.com/jackc/pgx/v5/pgxpool"
	sensitive "github.com/ruslanDantsov/password-manager/pkg/v1"
	"github.com/ruslanDantsov/password-manager/server/api"
	"github.com/ruslanDantsov/password-manager/server/api/interceptor"
	"github.com/ruslanDantsov/password-manager/server/repository"
	"google.golang.org/grpc"
	"net"
)

type Server struct {
	Host string
	Pool *pgxpool.Pool
}

func NewServer(host string) (*Server, error) {
	dbURL := "postgres://postgres:RedDawn_84@localhost:5432/password_manager?sslmode=disable"
	pool, err := pgxpool.New(context.Background(), dbURL)
	if err != nil {
		return nil, err
	}
	return &Server{
		Host: host,
		Pool: pool,
	}, nil
}

func (s *Server) Start(ctx context.Context) error {
	listener, err := net.Listen("tcp", s.Host)
	if err != nil {
		return fmt.Errorf("failed to listen on %s: %w", s.Host, err)
	}

	queries := repository.New(s.Pool)
	sensitiveDataHandler := api.NewSensitiveDataHandler(queries)

	grpcServer := grpc.NewServer(
		grpc.UnaryInterceptor(interceptor.AuthUnaryInterceptor(
			"/sensitivemanager.v1.SensitiveDataService/RegisterUser",
			"/sensitivemanager.v1.SensitiveDataService/LoginUser",
		)),
	)

	sensitive.RegisterSensitiveDataServiceServer(grpcServer, sensitiveDataHandler)

	fmt.Println("gRPC server started")
	return grpcServer.Serve(listener)
}

func (s *Server) Close() {
	//logger.Log.Info("Server shutting down...")

}
