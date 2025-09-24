package main

import (
	"context"
	"fmt"
	"github.com/ruslanDantsov/password-manager/client/app"
	"os"
	"os/signal"
	"syscall"
)

func main() {
	clientApp, err := app.NewClientApp("localhost:8090")
	if err != nil {
		fmt.Printf("Unable to config Client: %v", err)
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	if err := clientApp.Run(ctx); err != nil {
		fmt.Printf("Client start failed: %v", err.Error())
	}
}
