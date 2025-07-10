package main

import (
	"bytes"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"golang.org/x/crypto/bcrypt"
)

type AuthService interface {
	GenerateTokens(userID uuid.UUID, userAgent, ipAddress string) (*TokenPair, error)
	RefreshTokens(oldAccessToken, base64RefreshToken, userAgent, ipAddress string) (*TokenPair, error)
	ValidateAccessToken(tokenString string) (*CustomClaims, error)
	RevokeUserTokens(userID uuid.UUID) error
}

type TokenPair struct {
	AccessToken  string `json:"accessToken"`
	RefreshToken string `json:"refreshToken"`
}

type CustomClaims struct {
	UserID      uuid.UUID `json:"user_id"`
	TokenPairID uuid.UUID `json:"token_pair_id"`
	jwt.RegisteredClaims
}

type IPChangeNotification struct {
	UserID           uuid.UUID `json:"user_id"`
	StoredIP         string    `json:"stored_ip"`
	CurrentIP        string    `json:"current_ip"`
	UserAgent        string    `json:"user_agent"`
	Timestamp        time.Time `json:"timestamp"`
	NotificationType string    `json:"notification_type"`
}

type authServiceImpl struct {
	tokenRepo              TokenRepository
	jwtSecret              string
	webhookNotificationURL string
}

func NewAuthService(repo TokenRepository, jwtSecret string, webhookURL string) AuthService {
	return &authServiceImpl{
		tokenRepo:              repo,
		jwtSecret:              jwtSecret,
		webhookNotificationURL: webhookURL,
	}
}

func (s *authServiceImpl) GenerateTokens(userID uuid.UUID, userAgent, ipAddress string) (*TokenPair, error) {
	tokenPairID := uuid.New()

	accessTokenExpiresAt := time.Now().Add(15 * time.Minute)
	accessTokenClaims := CustomClaims{
		UserID:      userID,
		TokenPairID: tokenPairID,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(accessTokenExpiresAt),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
			Subject:   userID.String(),
		},
	}
	accessToken := jwt.NewWithClaims(jwt.SigningMethodHS512, accessTokenClaims)
	signedAccessToken, err := accessToken.SignedString([]byte(s.jwtSecret))
	if err != nil {
		log.Printf("Error signing access token for user %s: %v", userID, err)
		return nil, fmt.Errorf("failed to sign access token: %w", err)
	}

	refreshTokenBytes := make([]byte, 32)
	_, err = rand.Read(refreshTokenBytes)
	if err != nil {
		log.Printf("Error generating refresh token bytes for user %s: %v", userID, err)
		return nil, fmt.Errorf("failed to generate refresh token: %w", err)
	}
	rawRefreshToken := base64.RawURLEncoding.EncodeToString(refreshTokenBytes)

	hashedRefreshToken, err := bcrypt.GenerateFromPassword([]byte(rawRefreshToken), bcrypt.DefaultCost)
	if err != nil {
		log.Printf("Error hashing refresh token for user %s: %v", userID, err)
		return nil, fmt.Errorf("failed to hash refresh token: %w", err)
	}

	refreshTokenExpiresAt := time.Now().Add(7 * 24 * time.Hour)
	refreshTokenDB := &RefreshToken{
		ID:        tokenPairID,
		UserID:    userID,
		TokenHash: string(hashedRefreshToken),
		UserAgent: userAgent,
		IPAddress: ipAddress,
		ExpiresAt: refreshTokenExpiresAt,
		CreatedAt: time.Now(),
		RevokedAt: nil,
	}

	err = s.tokenRepo.Save(refreshTokenDB)
	if err != nil {
		return nil, fmt.Errorf("failed to save refresh token to database: %w", err)
	}

	return &TokenPair{
		AccessToken:  signedAccessToken,
		RefreshToken: rawRefreshToken,
	}, nil
}

func (s *authServiceImpl) RefreshTokens(oldAccessToken, base64RefreshToken, userAgent, ipAddress string) (*TokenPair, error) {
	claims := &CustomClaims{}
	token, err := jwt.ParseWithClaims(oldAccessToken, claims, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return []byte(s.jwtSecret), nil
	})

	if err != nil && !errors.Is(err, jwt.ErrTokenExpired) {
		log.Printf("Invalid old access token provided for refresh: %v", err)
		return nil, fmt.Errorf("invalid access token: %w", err)
	}
	// Если токен невалиден или не содержит нужных клеймов
	if !token.Valid && !errors.Is(err, jwt.ErrTokenExpired) {
		log.Printf("Access token is not valid for refresh: %v", err)
		return nil, errors.New("access token is not valid")
	}

	storedRefreshToken, err := s.tokenRepo.FindByUserIDAndID(claims.UserID, claims.TokenPairID)
	if err != nil {
		log.Printf("Refresh token not found or already revoked/expired for user %s, pair %s: %v", claims.UserID, claims.TokenPairID, err)
		return nil, errors.New("invalid or revoked refresh token")
	}

	if bcrypt.CompareHashAndPassword([]byte(storedRefreshToken.TokenHash), []byte(base64RefreshToken)) != nil {
		log.Printf("Attempted refresh with mismatched refresh token hash for user %s. Revoking all tokens.", claims.UserID)
		_ = s.tokenRepo.RevokeByUserID(claims.UserID)
		return nil, errors.New("invalid refresh token")
	}

	// Защита от повторного использования
	if storedRefreshToken.RevokedAt != nil || time.Now().After(storedRefreshToken.ExpiresAt) {
		log.Printf("Attempted to use a revoked or expired refresh token for user %s, pair %s", claims.UserID, claims.TokenPairID)
		return nil, errors.New("refresh token already used, revoked, or expired")
	}

	// Проверка User-Agent
	if storedRefreshToken.UserAgent != userAgent {
		log.Printf("User-Agent mismatch for user %s. Stored: '%s', Current: '%s'. Revoking all tokens.", claims.UserID, storedRefreshToken.UserAgent, userAgent)
		_ = s.tokenRepo.RevokeByUserID(claims.UserID)
		return nil, errors.New("user agent mismatch, all tokens revoked")
	}

	// Проверка IP-адреса
	if storedRefreshToken.IPAddress != ipAddress {
		log.Printf("IP Address change detected for user %s. Stored: '%s', Current: '%s'. Sending webhook notification.", claims.UserID, storedRefreshToken.IPAddress, ipAddress)

		if s.webhookNotificationURL != "" {
			notification := IPChangeNotification{
				UserID:           claims.UserID,
				StoredIP:         storedRefreshToken.IPAddress,
				CurrentIP:        ipAddress,
				UserAgent:        userAgent,
				Timestamp:        time.Now(),
				NotificationType: "IP_CHANGE_REFRESH",
			}

			go func(url string, data IPChangeNotification) {
				payload, err := json.Marshal(data)
				if err != nil {
					log.Printf("Error marshalling webhook payload for user %s: %v", data.UserID, err)
					return
				}

				req, err := http.NewRequest("POST", url, bytes.NewBuffer(payload))
				if err != nil {
					log.Printf("Error creating webhook request for user %s: %v", data.UserID, err)
					return
				}
				req.Header.Set("Content-Type", "application/json")

				client := &http.Client{Timeout: 10 * time.Second}
				resp, err := client.Do(req)
				if err != nil {
					log.Printf("Error sending webhook notification for user %s: %v", data.UserID, err)
					return
				}
				defer resp.Body.Close()

				if resp.StatusCode < 200 || resp.StatusCode >= 300 {
					bodyBytes, _ := io.ReadAll(resp.Body)
					log.Printf("Webhook notification for user %s failed with status %d: %s", data.UserID, resp.StatusCode, string(bodyBytes))
				} else {
					log.Printf("Webhook notification for user %s sent successfully. Status: %d", data.UserID, resp.StatusCode)
				}
			}(s.webhookNotificationURL, notification)
		} else {
			log.Println("Webhook notification URL is not configured (WEBHOOK_NOTIFICATION_URL is empty).")
		}
	}

	err = s.tokenRepo.RevokeByID(storedRefreshToken.ID)
	if err != nil {
		log.Printf("Error revoking old refresh token %s for user %s: %v", storedRefreshToken.ID, claims.UserID, err)
		return nil, fmt.Errorf("failed to revoke old refresh token: %w", err)
	}

	return s.GenerateTokens(claims.UserID, userAgent, ipAddress)
}

func (s *authServiceImpl) ValidateAccessToken(tokenString string) (*CustomClaims, error) {
	claims := &CustomClaims{}

	token, err := jwt.ParseWithClaims(tokenString, claims, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return []byte(s.jwtSecret), nil
	})

	if err != nil {
		log.Printf("Error parsing access token: %v", err)
		return nil, fmt.Errorf("invalid token: %w", err)
	}

	if !token.Valid {
		log.Printf("Access token is not valid (general check, claims: %+v)", claims)
		return nil, errors.New("access token is not valid")
	}

	if claims.UserID == uuid.Nil {
		return nil, errors.New("token claims missing user ID")
	}

	return claims, nil
}

func (s *authServiceImpl) RevokeUserTokens(userID uuid.UUID) error {
	err := s.tokenRepo.RevokeByUserID(userID)
	if err != nil {
		log.Printf("Error revoking all tokens for user %s: %v", userID, err)
		return fmt.Errorf("failed to revoke all tokens for user: %w", err)
	}
	return nil
}
