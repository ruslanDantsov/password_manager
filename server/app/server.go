package app

import (
	"context"
	"fmt"
	user "github.com/ruslanDantsov/password-manager/pkg/v1"
	"github.com/ruslanDantsov/password-manager/server/service"
	"google.golang.org/grpc"
	"net"
)

type Server struct {
	Host string
}

func NewServer(host string) (*Server, error) {
	return &Server{Host: host}, nil
}

func (s *Server) Start(ctx context.Context) error {
	listener, err := net.Listen("tcp", s.Host)
	if err != nil {
		return fmt.Errorf("failed to listen on %s: %w", s.Host, err)
	}

	userService := service.NewUserService()

	grpcServer := grpc.NewServer()
	user.RegisterAuthServiceServer(grpcServer, userService)

	fmt.Println("gRPC server started")
	return grpcServer.Serve(listener)
}

// Close завершает работу приложения.
func (s *Server) Close() {
	//logger.Log.Info("Server shutting down...")

}
