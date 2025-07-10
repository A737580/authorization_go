package main

import (
	"log"
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
)

// AuthMiddleware - middleware для проверки Access Token.
// @Summary Verify Access Token
// @Description This middleware checks the Authorization header for a valid Bearer token.
// @Tags middleware
// @Security BearerAuth
// @Failure 401 {object} ErrorResponse "Authorization header required or invalid token"
// @Router /api/v1/some-protected-route [get]
// Примечание: Для middleware @Router аннотация может быть немного некорректной в UI, но помогает с генерацией.
func AuthMiddleware(authService AuthService) gin.HandlerFunc {
	return func(c *gin.Context) {
		authHeader := c.GetHeader("Authorization")
		if authHeader == "" {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Authorization header required"})
			c.Abort()
			return
		}

		parts := strings.Split(authHeader, " ")
		if len(parts) != 2 || parts[0] != "Bearer" {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Authorization header format must be Bearer {token}"})
			c.Abort()
			return
		}

		accessToken := parts[1]
		claims, err := authService.ValidateAccessToken(accessToken)
		if err != nil {
			log.Printf("Access token validation failed: %v", err)
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid or expired access token", "details": err.Error()})
			c.Abort()
			return
		}

		refreshTokenDB, err := tokenRepo.FindByID(claims.TokenPairID)
		if err != nil {
			log.Printf("Error finding associated refresh token for access token (pairID: %s): %v", claims.TokenPairID, err)
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Associated refresh token not found or database error"})
			c.Abort()
			return
		}

		if refreshTokenDB.RevokedAt != nil {
			log.Printf("Associated refresh token (pairID: %s) for user %s has been revoked. Access token is invalid.",
				claims.TokenPairID, claims.UserID)
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Associated token revoked, please re-authenticate"})
			c.Abort()
			return
		}

		if refreshTokenDB.UserID != claims.UserID {
			log.Printf("UserID mismatch between AccessToken claims (%s) and stored RefreshToken (%s).", claims.UserID, refreshTokenDB.UserID)
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Token ownership mismatch"})
			c.Abort()
			return
		}
		c.Set("claims", claims)
		c.Set("userID", claims.UserID)
		c.Next()

	}
}
