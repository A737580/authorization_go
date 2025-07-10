package main

import (
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
)

type RefreshTokenPayload struct {
	TokenPairID  string    `json:"token_pair_id"`
	UserID       uuid.UUID `json:"user_id"`
	RefreshToken string    `json:"refresh_token"`
	UserAgent    string    `json:"user_agent"`
	IPAddress    string    `json:"ip_address"`
	ExpiresAt    time.Time `json:"expires_at"`
	CreatedAt    time.Time `json:"created_at"`
}

type AuthClaims struct {
	UserID      string `json:"user_id"`
	TokenPairID string `json:"token_pair_id"`
	jwt.RegisteredClaims
}

type ErrorResponse struct {
	Error   string `json:"error"`
	Details string `json:"details,omitempty"`
}

type MessageResponse struct {
	Message string `json:"message"`
}

type UserIDResponse struct {
	UserID string `json:"user_id"`
}

type GenerateTokenRequest struct {
	UserID string `json:"user_id" binding:"required"`
}

type RefreshTokenRequest struct {
	RefreshToken string `json:"refresh_token" binding:"required"`
	AccessToken  string `json:"access_token" binding:"required"`
}

type RevokeTokenRequest struct {
	UserID string `json:"user_id" binding:"required"`
}
