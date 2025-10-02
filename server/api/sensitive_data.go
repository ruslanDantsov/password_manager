package api

import (
	"context"
	"crypto/rand"
	"fmt"
	"github.com/golang-jwt/jwt/v5"
	"github.com/ruslanDantsov/password-manager/pkg/crypto"
	sensitive "github.com/ruslanDantsov/password-manager/pkg/v1"
	"github.com/ruslanDantsov/password-manager/server/repository"
	"golang.org/x/crypto/bcrypt"
	"golang.org/x/crypto/scrypt"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"time"
)

var AccessTokenSecret = "very-secret-access"

const (
	SecretDataTypeCredentials = "credentials"
	SecretDataTypeCard        = "card"
	SecretDataTypeNote        = "note"
)

type SensitiveDataHandler struct {
	sensitive.UnimplementedSensitiveDataServiceServer
	querier repository.Querier
}

func NewSensitiveDataHandler(querier repository.Querier) *SensitiveDataHandler {
	return &SensitiveDataHandler{
		querier: querier,
	}
}

func (s *SensitiveDataHandler) RegisterUser(ctx context.Context, req *sensitive.RegisterUserRequest) (*sensitive.RegisterUserResponse, error) {
	fmt.Println("Start logic for user registration")
	if err := req.ValidateAll(); err != nil {
		return nil, status.Error(codes.InvalidArgument, err.Error())
	}

	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(req.Password), bcrypt.DefaultCost)
	if err != nil {
		return nil, status.Error(codes.Internal, "failed to hash password")
	}

	dataKey := make([]byte, 32) // AES-256
	_, _ = rand.Read(dataKey)

	salt := make([]byte, 16)
	_, _ = rand.Read(salt)
	kdfKey, _ := scrypt.Key([]byte(req.Password), salt, 32768, 8, 1, 32)
	encryptedDataKey, _ := crypto.Encrypt(dataKey, kdfKey)

	params := repository.CreateUserParams{
		Email:            req.Email,
		Salt:             salt,
		EncryptedDataKey: encryptedDataKey,
		PasswordHash:     string(hashedPassword),
		DisplayName:      &req.DisplayName,
	}

	createdUser, err := s.querier.CreateUser(ctx, params)
	if err != nil {
		if err.Error() == "pq: duplicate key value violates unique constraint" {
			return nil, status.Error(codes.AlreadyExists, "user with this email already exists")
		}
		return nil, status.Error(codes.Internal, fmt.Sprintf("failed to create user: %v", err))
	}

	fmt.Println("User register successfully")

	return &sensitive.RegisterUserResponse{
		UserId: createdUser.ID,
	}, nil

}

func (s *SensitiveDataHandler) LoginUser(ctx context.Context, req *sensitive.LoginUserRequest) (*sensitive.LoginUserResponse, error) {
	fmt.Println("Start logic for user login")
	if req.Email == "" || req.Password == "" {
		return nil, status.Error(codes.InvalidArgument, "email and password are required")
	}

	dbUser, err := s.querier.GetUserByEmail(ctx, req.Email)
	if err != nil {
		return nil, status.Error(codes.Unauthenticated, "invalid email or password")
	}

	err = bcrypt.CompareHashAndPassword([]byte(dbUser.PasswordHash), []byte(req.Password))
	if err != nil {
		return nil, status.Error(codes.Unauthenticated, "invalid email or password")
	}

	accessToken, err := s.generateAccessToken(dbUser.ID)
	if err != nil {
		return nil, status.Error(codes.Internal, "failed to generate access token")
	}

	fmt.Println("User login successfully")

	return &sensitive.LoginUserResponse{
		UserId:           dbUser.ID,
		AccessToken:      accessToken,
		Salt:             dbUser.Salt,
		EncryptedDataKey: dbUser.EncryptedDataKey,
	}, nil
}

func (s *SensitiveDataHandler) AddCredentialData(ctx context.Context, req *sensitive.AddCredentialDataRequest) (*sensitive.AddCredentialDataResponse, error) {
	userID, ok := ctx.Value("userID").(int64)
	if !ok {
		return nil, status.Error(codes.Unauthenticated, "userID not found in context")
	}

	secretData, err := s.querier.CreateSecretData(ctx, repository.CreateSecretDataParams{
		UserID:      userID,
		Type:        SecretDataTypeCredentials,
		ServiceName: req.ServiceName,
		CreatedAt:   time.Now(),
	})
	if err != nil {
		return nil, status.Errorf(codes.Internal, "failed to create secret data: %v", err)
	}

	_, err = s.querier.CreateCredential(ctx, repository.CreateCredentialParams{
		SecretDataID:      secretData.ID,
		Login:             req.Login,
		PasswordEncrypted: req.Password,
	})
	if err != nil {
		return nil, status.Errorf(codes.Internal, "failed to save credentials: %v", err)
	}

	return &sensitive.AddCredentialDataResponse{
		SecretDataId: secretData.ID,
	}, nil

}

func (s *SensitiveDataHandler) GetCredentialDataList(ctx context.Context, req *sensitive.GetCredentialDataListRequest) (*sensitive.GetCredentialDataListResponse, error) {
	userID, ok := ctx.Value("userID").(int64)
	if !ok {
		return nil, status.Error(codes.Unauthenticated, "userID not found in context")
	}

	rows, err := s.querier.GetUserCredentials(ctx, userID)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "failed to get credentials: %v", err)
	}

	credentials := make([]*sensitive.CredentialData, 0, len(rows))
	for _, row := range rows {

		credentials = append(credentials, &sensitive.CredentialData{
			ServiceName: row.ServiceName,
			Login:       row.Login,
			Password:    row.PasswordEncrypted,
		})
	}

	return &sensitive.GetCredentialDataListResponse{
		CredentialData: credentials,
	}, nil

}

func (s *SensitiveDataHandler) AddTextData(ctx context.Context, req *sensitive.AddTextDataRequest) (*sensitive.AddTextDataResponse, error) {
	userID, ok := ctx.Value("userID").(int64)
	if !ok {
		return nil, status.Error(codes.Unauthenticated, "userID not found in context")
	}

	secretData, err := s.querier.CreateSecretData(ctx, repository.CreateSecretDataParams{
		UserID:      userID,
		Type:        SecretDataTypeNote,
		ServiceName: req.ServiceName,
		CreatedAt:   time.Now(),
	})
	if err != nil {
		return nil, status.Errorf(codes.Internal, "failed to create secret data: %v", err)
	}

	_, err = s.querier.CreateTextData(ctx, repository.CreateTextDataParams{
		SecretDataID:     secretData.ID,
		ContentEncrypted: req.Data,
	})
	if err != nil {
		return nil, status.Errorf(codes.Internal, "failed to save note: %v", err)
	}

	return &sensitive.AddTextDataResponse{
		SecretDataId: secretData.ID,
	}, nil

}

func (s *SensitiveDataHandler) GetTextDataList(ctx context.Context, req *sensitive.GetTextDataListRequest) (*sensitive.GetTextDataListResponse, error) {
	userID, ok := ctx.Value("userID").(int64)
	if !ok {
		return nil, status.Error(codes.Unauthenticated, "userID not found in context")
	}

	rows, err := s.querier.GetUserTextData(ctx, userID)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "failed to get notes: %v", err)
	}

	notes := make([]*sensitive.NoteData, 0, len(rows))
	for _, row := range rows {

		notes = append(notes, &sensitive.NoteData{
			ServiceName: row.ServiceName,
			Data:        row.ContentEncrypted,
		})
	}

	return &sensitive.GetTextDataListResponse{
		NoteData: notes,
	}, nil

}

func (s *SensitiveDataHandler) AddCardData(ctx context.Context, req *sensitive.AddCardDataRequest) (*sensitive.AddCardDataResponse, error) {
	userID, ok := ctx.Value("userID").(int64)
	if !ok {
		return nil, status.Error(codes.Unauthenticated, "userID not found in context")
	}

	secretData, err := s.querier.CreateSecretData(ctx, repository.CreateSecretDataParams{
		UserID:      userID,
		Type:        SecretDataTypeCard,
		ServiceName: req.ServiceName,
		CreatedAt:   time.Now(),
	})
	if err != nil {
		return nil, status.Errorf(codes.Internal, "failed to create secret data: %v", err)
	}

	_, err = s.querier.CreateBankCard(ctx, repository.CreateBankCardParams{
		SecretDataID:        secretData.ID,
		CardholderName:      req.CardholderName,
		CardNumberEncrypted: req.CardNumberEncrypted,
		ExpiryMonth:         req.ExpiryMonth,
		ExpiryYear:          req.ExpiryYear,
		CvvEncrypted:        req.CvvEncrypted,
	})

	if err != nil {
		return nil, status.Errorf(codes.Internal, "failed to save bank card: %v", err)
	}

	return &sensitive.AddCardDataResponse{
		SecretDataId: secretData.ID,
	}, nil

}

func (s *SensitiveDataHandler) GetCardDataList(ctx context.Context, req *sensitive.GetCardDataListRequest) (*sensitive.GetCardDataListResponse, error) {
	userID, ok := ctx.Value("userID").(int64)
	if !ok {
		return nil, status.Error(codes.Unauthenticated, "userID not found in context")
	}

	rows, err := s.querier.GetUserBankCards(ctx, userID)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "failed to get bank cards: %v", err)
	}

	cards := make([]*sensitive.CardData, 0, len(rows))
	for _, row := range rows {

		cards = append(cards, &sensitive.CardData{
			ServiceName:         row.ServiceName,
			CardholderName:      row.CardholderName,
			CardNumberEncrypted: row.CardNumberEncrypted,
			ExpiryMonth:         row.ExpiryMonth,
			ExpiryYear:          row.ExpiryYear,
			CvvEncrypted:        row.CvvEncrypted,
		})
	}

	return &sensitive.GetCardDataListResponse{
		CardData: cards,
	}, nil

}

func (s *SensitiveDataHandler) generateAccessToken(userID int64) (string, error) {
	expirationTime := time.Now().Add(time.Hour * 1).Unix()
	claims := jwt.MapClaims{
		"id":  userID,
		"exp": expirationTime,
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)

	tokenString, err := token.SignedString([]byte(AccessTokenSecret))
	return tokenString, err
}
