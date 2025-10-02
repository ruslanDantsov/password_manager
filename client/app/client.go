package app

import (
	"context"
	"fmt"
	"github.com/manifoldco/promptui"
	"github.com/ruslanDantsov/password-manager/client/api"
	sensitive "github.com/ruslanDantsov/password-manager/pkg/v1"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

type Session struct {
	JwtToken  string
	CryptoKey []byte
}

type ClientApp struct {
	Host                    string
	sensitiveDataClient     sensitive.SensitiveDataServiceClient
	UserRegistrationHandler func(ctx context.Context, email, password, name string) error
	UserLoginHandler        func(ctx context.Context, email, password string) (string, []byte, error)
	AddCredHandler          func(ctx context.Context, serviceName, login, password, authToken string, cryptoKey []byte) error
	GetCredListHandler      func(ctx context.Context, authToken string, cryptoKey []byte) ([]*sensitive.CredentialData, error)
	AddNoteHandler          func(ctx context.Context, serviceName, note, authToken string, cryptoKey []byte) error
	GetNoteListHandler      func(ctx context.Context, authToken string, cryptoKey []byte) ([]*sensitive.NoteData, error)
}

func NewClientApp(host string) (*ClientApp, error) {
	conn, err := grpc.NewClient(host, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		return nil, fmt.Errorf("failed to connect to gRPC server: %w", err)
	}
	sensitiveDataClient := sensitive.NewSensitiveDataServiceClient(conn)

	return &ClientApp{
		sensitiveDataClient:     sensitiveDataClient,
		Host:                    host,
		UserRegistrationHandler: api.NewUserRegisterHandler(sensitiveDataClient),
		UserLoginHandler:        api.NewUserLoginHandler(sensitiveDataClient),
		AddCredHandler:          api.NewAddCredHandler(sensitiveDataClient),
		GetCredListHandler:      api.NewGetCredListHandler(sensitiveDataClient),
		AddNoteHandler:          api.NewAddNoteHandler(sensitiveDataClient),
		GetNoteListHandler:      api.NewGetNoteListHandler(sensitiveDataClient),
	}, nil
}

func (c *ClientApp) Run(ctx context.Context) error {
	session := &Session{}

	for {
		menu := promptui.Select{
			Label: "Choose an option for user",
			Items: []string{"Register User", "Login", "Exit"},
		}
		_, choice, err := menu.Run()
		if err != nil {
			fmt.Printf("Prompt failed %v\n", err)
			return nil
		}

		switch choice {
		case "Register User":
			email := promptInput("Email")
			password := promptPassword("Password")
			name := promptInput("Name")

			err := c.UserRegistrationHandler(ctx, email, password, name)

			if err != nil {
				fmt.Printf("❌ could not register: %v\n", err)
			} else {
				fmt.Println("✅ Registered successfully")
			}

		case "Login":
			email := promptInput("Email")
			password := promptPassword("Password")

			jwtToken, dataKey, err := c.UserLoginHandler(ctx, email, password)

			if err != nil {
				fmt.Printf("❌ could not login: %v\n", err)
			} else {
				fmt.Println("✅ Login successful")

				session.JwtToken = jwtToken
				session.CryptoKey = dataKey
				mainMenu(ctx, c.sensitiveDataClient, session, c)
			}

		case "Exit":
			fmt.Println("👋 Bye")
			return nil
		}
	}
}

func mainMenu(ctx context.Context, client sensitive.SensitiveDataServiceClient, session *Session, c *ClientApp) {
	for {
		menu := promptui.Select{
			Label: "Main Menu",
			Items: []string{"Credential Data", "Text Data", "Logout"},
		}
		_, choice, err := menu.Run()
		if err != nil {
			fmt.Printf("Prompt failed %v\n", err)
			return
		}

		switch choice {
		case "Credential Data":
			credentialDataMenu(ctx, session, c)
		case "Text Data":
			textDataMenu(ctx, session, c)
		case "Logout":
			session.JwtToken = ""
			fmt.Println("👋 Logging out...")
			return
		}
	}
}

func credentialDataMenu(ctx context.Context, session *Session, c *ClientApp) {
	for {
		menu := promptui.Select{
			Label: "Credential Data Menu",
			Items: []string{"Add Login and Password", "Get List", "Back"},
		}
		_, choice, err := menu.Run()
		if err != nil {
			fmt.Printf("Prompt failed %v\n", err)
			return
		}

		switch choice {
		case "Get List":
			fmt.Println("📋 Fetching list of saved credentials...")

			credList, err := c.GetCredListHandler(ctx, session.JwtToken, session.CryptoKey)

			if err != nil {
				fmt.Printf("❌ Error: %v\n", err)
			} else {
				if len(credList) == 0 {
					fmt.Println("📭 No credentials saved yet.")
				} else {
					for i, cred := range credList {
						if err == nil {
							fmt.Printf("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n")
							fmt.Printf("%d. %s\n", i+1, cred.ServiceName)
							fmt.Printf("   Login:      %s\n", cred.Login)
							fmt.Printf("   Password 🔐:   %s\n", string(cred.Password))
						}
					}
					fmt.Printf("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n\n")
				}
			}

		case "Add Login and Password":
			fmt.Printf("➕ Adding new credentials...\n")
			serviceName := promptInput("Service Name (e.g., Gmail, Facebook)")
			login := promptInput("Login")
			password := promptPassword("Password")
			err := c.AddCredHandler(ctx, serviceName, login, password, session.JwtToken, session.CryptoKey)
			if err != nil {
				fmt.Printf("❌ Error: %v\n", err)
			} else {
				fmt.Println("✅ Credential added successfully")
			}

		case "Back":
			return
		}
	}
}

func textDataMenu(ctx context.Context, session *Session, c *ClientApp) {
	for {
		menu := promptui.Select{
			Label: "Note Data Menu",
			Items: []string{"Add Note", "Get List", "Back"},
		}
		_, choice, err := menu.Run()
		if err != nil {
			fmt.Printf("Prompt failed %v\n", err)
			return
		}

		switch choice {
		case "Get List":
			fmt.Println("📋 Fetching list of saved notes...")

			noteList, err := c.GetNoteListHandler(ctx, session.JwtToken, session.CryptoKey)

			if err != nil {
				fmt.Printf("❌ Error: %v\n", err)
			} else {
				if len(noteList) == 0 {
					fmt.Println("📭 No notes saved yet.")
				} else {
					for i, note := range noteList {
						if err == nil {
							fmt.Printf("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n")
							fmt.Printf("%d. %s\n", i+1, note.ServiceName)
							fmt.Printf("   Data 🔐: %s\n", note.Data)
						}
					}
					fmt.Printf("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n\n")
				}
			}

		case "Add Note":
			fmt.Printf("➕ Adding new note...\n")
			label := promptInput("Label")
			data := promptInput("Data")
			err := c.AddNoteHandler(ctx, label, data, session.JwtToken, session.CryptoKey)
			if err != nil {
				fmt.Printf("❌ Error: %v\n", err)
			} else {
				fmt.Println("✅ Note added successfully")
			}

		case "Back":
			return
		}
	}
}

func promptInput(label string) string {
	prompt := promptui.Prompt{
		Label: label,
	}
	result, err := prompt.Run()
	if err != nil {
		fmt.Printf("Prompt failed %v\n", err)
		return ""
	}
	return result
}

func promptPassword(label string) string {
	prompt := promptui.Prompt{
		Label: label,
		Mask:  '*',
	}
	result, err := prompt.Run()
	if err != nil {
		fmt.Printf("Prompt failed %v\n", err)
		return ""
	}
	return result
}
