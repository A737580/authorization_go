package main

import (
	"log"
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
)

type AuthHandlers struct {
	authService AuthService
}

func NewAuthHandlers(service AuthService) *AuthHandlers {
	return &AuthHandlers{
		authService: service,
	}
}

// GenerateTokensHandler
// @Summary Generate new access and refresh tokens
// @Description Generates a new pair of access and refresh tokens for a given user ID.
// @Description **Пример user_id для тестирования:** `123e4567-e89b-12d3-a456-426614174000`
// @Tags auth
// @Accept json
// @Produce json
// @Success 200 {object} TokenPair "Successfully generated tokens"
// @Failure 400 {object} ErrorResponse "Invalid request payload or User ID format"
// @Failure 500 {object} ErrorResponse "Failed to generate tokens"
// @Router /auth/generate [post]
// @Param request body GenerateTokenRequest true "User ID for whom tokens are generated"
func (h *AuthHandlers) GenerateTokensHandler(c *gin.Context) {
	var req struct {
		UserID string `json:"user_id" binding:"required"`
	}

	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request payload", "details": err.Error()})
		return
	}

	userID, err := uuid.Parse(req.UserID)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid User ID format", "details": err.Error()})
		return
	}

	userAgent := c.GetHeader("User-Agent")
	ipAddress := c.ClientIP()

	tokenPair, err := h.authService.GenerateTokens(userID, userAgent, ipAddress)
	if err != nil {
		log.Printf("Error generating tokens for user %s: %v", userID, err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to generate tokens", "details": err.Error()})
		return
	}

	c.JSON(http.StatusOK, tokenPair)
}

// RefreshTokensHandler
// @Summary Refresh access and refresh tokens
// @Description Refreshes the token pair using an old access token and refresh token.
// @Tags auth
// @Accept json
// @Produce json
// @Success 200 {object} TokenPair "Successfully refreshed tokens"
// @Failure 400 {object} ErrorResponse "Invalid request payload"
// @Failure 401 {object} ErrorResponse "Authentication failed (invalid, revoked, or expired token/user agent mismatch)"
// @Failure 500 {object} ErrorResponse "Failed to refresh tokens"
// @Router /auth/refresh [post]
// @Param request body RefreshTokenRequest true "Token refresh request"
func (h *AuthHandlers) RefreshTokensHandler(c *gin.Context) {
	var req struct {
		RefreshToken string `json:"refresh_token" binding:"required"`
		AccessToken  string `json:"access_token" binding:"required"`
	}

	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request payload", "details": err.Error()})
		return
	}

	userAgent := c.GetHeader("User-Agent")
	ipAddress := c.ClientIP()

	tokenPair, err := h.authService.RefreshTokens(req.AccessToken, req.RefreshToken, userAgent, ipAddress)
	if err != nil {
		log.Printf("Error refreshing tokens: %v", err)
		// В зависимости от типа ошибки, можно вернуть более специфичный статус
		if strings.Contains(err.Error(), "invalid access token") || strings.Contains(err.Error(), "invalid refresh token") ||
			strings.Contains(err.Error(), "refresh token already used, revoked, or expired") || strings.Contains(err.Error(), "user agent mismatch") {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Authentication failed", "details": err.Error()})
		} else {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to refresh tokens", "details": err.Error()})
		}
		return
	}

	c.JSON(http.StatusOK, tokenPair)
}

// GetCurrentUserGUIDHandler
// @Summary Get current user's GUID
// @Description Returns the GUID of the currently authenticated user.
// @Tags user
// @Security BearerAuth
// @Produce json
// @Success 200 {object} UserIDResponse "User ID retrieved successfully"
// @Failure 401 {object} ErrorResponse "Unauthorized"
// @Failure 500 {object} ErrorResponse "Internal server error"
// @Router /user/me [get]
func (h *AuthHandlers) GetCurrentUserGUIDHandler(c *gin.Context) {
	userID, exists := c.Get("userID")

	if !exists {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "User ID not found in context"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"user_id": userID})
}

// RevokeUserTokensHandler
// @Summary Revoke all refresh tokens for a user
// @Description Revokes all active refresh tokens for the specified user ID.
// @Tags admin
// @Accept json
// @Produce json
// @Success 200 {object} MessageResponse "All tokens for user revoked successfully"
// @Failure 400 {object} ErrorResponse "Invalid request payload or User ID format"
// @Failure 500 {object} ErrorResponse "Failed to revoke tokens"
// @Router /auth/revoke [post]
// @Param request body RevokeTokenRequest true "User ID whose tokens are to be revoked"
func (h *AuthHandlers) RevokeUserTokensHandler(c *gin.Context) {
	var req struct {
		UserID string `json:"user_id" binding:"required"`
	}

	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request payload", "details": err.Error()})
		return
	}

	userID, err := uuid.Parse(req.UserID)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid User ID format", "details": err.Error()})
		return
	}

	err = h.authService.RevokeUserTokens(userID)
	if err != nil {
		log.Printf("Error revoking tokens for user %s: %v", userID, err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to revoke tokens", "details": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "All tokens for user revoked successfully"})
}
