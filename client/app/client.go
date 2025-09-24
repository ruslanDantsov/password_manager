package app

import (
	"context"
	"errors"
	"fmt"
	user "github.com/ruslanDantsov/password-manager/pkg/v1"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

type ClientApp struct {
	Host       string
	userClient user.AuthServiceClient
}

func NewClientApp(host string) (*ClientApp, error) {
	conn, err := grpc.NewClient(host, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		return nil, fmt.Errorf("failed to connect to gRPC server: %w", err)
	}
	userClient := user.NewAuthServiceClient(conn)

	return &ClientApp{
		userClient: userClient,
		Host:       host,
	}, nil
}

func (c *ClientApp) Run(ctx context.Context) error {
	for {
		fmt.Println("Please choose the option: ")
		fmt.Println("1. Register")
		fmt.Println("2. Login")
		fmt.Println("3. Exit")
		var choice int
		fmt.Scan(&choice)
		switch choice {
		case 1:
			//var login, password string
			//fmt.Print("Enter login: ")
			//fmt.Scan(&login)
			//fmt.Print("Enter password: ")
			//fmt.Scan(&password)

			// Call registration function
			_, err := c.userClient.Register(ctx, &user.RegisterRequest{
				Email:       "login",
				Password:    "password",
				DisplayName: "my name",
			})
			if err != nil {
				return errors.New(fmt.Sprintf("could not register: %v", err))
			}

		case 2:
			var login, password string
			fmt.Print("Enter login: ")
			fmt.Scan(&login)
			fmt.Print("Enter password: ")
			fmt.Scan(&password)
			// Call login function
		case 3:
			fmt.Println("Exiting...")
			return nil
		default:
			fmt.Println("Invalid choice, please try again.")

		}
	}
}
