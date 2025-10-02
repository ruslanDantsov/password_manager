package interceptor

import (
	"context"
	"github.com/golang-jwt/jwt/v5"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
	"strings"
)

var AccessTokenSecret = "very-secret-access"

func AuthUnaryInterceptor(skipMethods ...string) grpc.UnaryServerInterceptor {
	skip := make(map[string]struct{})
	for _, m := range skipMethods {
		skip[m] = struct{}{}
	}
	return func(
		ctx context.Context,
		req interface{},
		info *grpc.UnaryServerInfo,
		handler grpc.UnaryHandler,
	) (interface{}, error) {
		if _, ok := skip[info.FullMethod]; ok {
			return handler(ctx, req)
		}

		md, ok := metadata.FromIncomingContext(ctx)
		if !ok {
			return nil, status.Error(codes.Unauthenticated, "metadata not found")
		}

		tokens := md.Get("authorization")
		if len(tokens) == 0 {
			return nil, status.Error(codes.Unauthenticated, "authorization token not found")
		}

		tokenString := strings.TrimPrefix(tokens[0], "Bearer ")

		token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
			if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
				return nil, status.Error(codes.Unauthenticated, "unexpected signing method")
			}
			return []byte(AccessTokenSecret), nil
		})

		if err != nil || !token.Valid {
			return nil, status.Error(codes.Unauthenticated, "invalid token")
		}

		claims, ok := token.Claims.(jwt.MapClaims)
		if !ok {
			return nil, status.Error(codes.Unauthenticated, "invalid token claims")
		}

		if idFloat, ok := claims["id"].(float64); ok {
			userID := int64(idFloat)

			ctx = context.WithValue(ctx, "userID", userID)
		} else {
			return nil, status.Error(codes.Unauthenticated, "invalid token claims")
		}

		return handler(ctx, req)
	}
}
