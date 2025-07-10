package main

import (
	"database/sql"
	"errors"
	"fmt"
	"log"

	"github.com/google/uuid"
)

type TokenRepository interface {
	Save(token *RefreshToken) error
	FindByUserIDAndID(userID, tokenID uuid.UUID) (*RefreshToken, error)
	RevokeByUserID(userID uuid.UUID) error
	RevokeByID(tokenID uuid.UUID) error
	FindByID(tokenID uuid.UUID) (*RefreshToken, error)
}

type postgresTokenRepository struct {
	db *sql.DB
}

func NewPostgresTokenRepository(db *sql.DB) TokenRepository {
	return &postgresTokenRepository{db: db}
}

func (r *postgresTokenRepository) Save(token *RefreshToken) error {
	query := `
		INSERT INTO refresh_tokens (id, user_id, token_hash, user_agent, ip_address, expires_at, created_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7)
	`
	_, err := r.db.Exec(
		query,
		token.ID,
		token.UserID,
		token.TokenHash,
		token.UserAgent,
		token.IPAddress,
		token.ExpiresAt,
		token.CreatedAt,
	)
	if err != nil {
		log.Printf("Error saving refresh token: %v", err)
		return fmt.Errorf("failed to save refresh token: %w", err)
	}
	return nil
}

func (r *postgresTokenRepository) FindByUserIDAndID(userID, tokenID uuid.UUID) (*RefreshToken, error) {
	query := `
		SELECT id, user_id, token_hash, user_agent, ip_address, expires_at, created_at, revoked_at
		FROM refresh_tokens
		WHERE user_id = $1 AND id = $2 AND revoked_at IS NULL AND expires_at > NOW()
	`
	token := &RefreshToken{}
	var revokedAt sql.NullTime

	err := r.db.QueryRow(query, userID, tokenID).Scan(
		&token.ID,
		&token.UserID,
		&token.TokenHash,
		&token.UserAgent,
		&token.IPAddress,
		&token.ExpiresAt,
		&token.CreatedAt,
		&revokedAt,
	)

	if err != nil {
		if err == sql.ErrNoRows {
			return nil, fmt.Errorf("refresh token not found or already expired/revoked")
		}
		log.Printf("Error finding refresh token by user_id and id: %v", err)
		return nil, fmt.Errorf("failed to find refresh token: %w", err)
	}

	if revokedAt.Valid {
		token.RevokedAt = &revokedAt.Time
	} else {
		token.RevokedAt = nil
	}

	return token, nil
}

func (r *postgresTokenRepository) RevokeByUserID(userID uuid.UUID) error {
	query := `
		UPDATE refresh_tokens
		SET revoked_at = NOW()
		WHERE user_id = $1 AND revoked_at IS NULL
	`
	_, err := r.db.Exec(query, userID)
	if err != nil {
		log.Printf("Error revoking tokens for user %s: %v", userID, err)
		return fmt.Errorf("failed to revoke tokens for user: %w", err)
	}
	return nil
}

func (r *postgresTokenRepository) RevokeByID(tokenID uuid.UUID) error {
	query := `
		UPDATE refresh_tokens
		SET revoked_at = NOW()
		WHERE id = $1 AND revoked_at IS NULL
	`
	_, err := r.db.Exec(query, tokenID)
	if err != nil {
		log.Printf("Error revoking token %s: %v", tokenID, err)
		return fmt.Errorf("failed to revoke token by ID: %w", err)
	}
	return nil
}

func (r *postgresTokenRepository) FindByID(tokenID uuid.UUID) (*RefreshToken, error) {
	var rt RefreshToken
	query := `
		SELECT id, user_id, token_hash, user_agent, ip_address, expires_at, created_at, revoked_at
		FROM refresh_tokens
		WHERE id = $1`

	err := r.db.QueryRow(query, tokenID).Scan(
		&rt.ID, &rt.UserID, &rt.TokenHash, &rt.UserAgent,
		&rt.IPAddress, &rt.ExpiresAt, &rt.CreatedAt, &rt.RevokedAt,
	)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, fmt.Errorf("refresh token with ID %s not found", tokenID)
		}
		return nil, fmt.Errorf("failed to find refresh token by ID %s: %w", tokenID, err)
	}
	return &rt, nil
}
