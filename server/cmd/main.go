package main

import (
	"context"
	"fmt"
	"github.com/ruslanDantsov/password-manager/server/app"
	"os"
	"os/signal"
	"syscall"
)

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	server, err := app.NewServer("localhost:8090")
	if err != nil {
		fmt.Println("Unable to config Server")
	}

	if err := server.Start(ctx); err != nil {
		fmt.Printf("Password manager start failed: %v\n", err)
	}

}
