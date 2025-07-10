package main

import (
	"time"

	"github.com/google/uuid"
)

type RefreshToken struct {
	ID        uuid.UUID  `db:"id"`         // Уникальный идентификатор refresh-токена
	UserID    uuid.UUID  `db:"user_id"`    // GUID пользователя
	TokenHash string     `db:"token_hash"` // bcrypt-хэш refresh-токена
	UserAgent string     `db:"user_agent"` // User-Agent клиента
	IPAddress string     `db:"ip_address"` // IP-адрес клиента
	ExpiresAt time.Time  `db:"expires_at"` // Время истечения срока действия
	CreatedAt time.Time  `db:"created_at"` // Время создания записи
	RevokedAt *time.Time `db:"revoked_at"` // Время отзыва токена (может быть NULL)
}
