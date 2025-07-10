# AuthService (на Go)

Краткое описание проекта:  
Сервис аутентификации, реализованный на Go с использованием фреймворка `gin`. Предоставляет базовый функционал авторизации по access и refresh токенам, защиту от повторного использования, webhook-уведомления и валидацию IP/User-Agent.

## 📦 Стек технологий

- Go 1.24
- Gin — HTTP-фреймворк
- PostgreSQL — база данных
- JWT (github.com/golang-jwt/jwt/v5) — для генерации access-токенов
- bcrypt (golang.org/x/crypto/bcrypt) — хэширование refresh-токенов
- UUID (github.com/google/uuid) — идентификаторы пользователей и токенов
- Swag (github.com/swaggo/gin-swagger) — автогенерация Swagger-документации
- Docker & Docker Compose — контейнеризация и запуск

## 📋 Требования к программе

| Требование | Выполнено |
|-----------|-----------|
| JWT access токен формата HS512 без хранения в БД | ✅ |
| Refresh токен хранится в виде bcrypt-хэша | ✅ |
| Access/Refresh выдаются только в паре | ✅ |
| Проверка User-Agent при refresh | ✅ |
| Проверка IP и webhook при refresh с нового IP | ✅ |
| Защита для refresh токенов | ✅ |
| Защищённый эндпоинт для получения GUID пользователя | ✅ |
| Logout (деавторизация пользователя) | ✅ |
| Swagger-документация со статусами и примерами | ✅ |
| Docker Compose с запуском одной командой | ✅ |

## Структура проекта
```txt
authorization_go/
├── handlers/            # Логика обработки HTTP-запросов
├── docs/                # Swagger-документация
├── middleware/          # Middleware для аутентификации 
├── models/              # Структуры данных 
├── api_responses/       # Структуры данных для отображения в swagger
├── repositories/        # Функции для взаимодействия с базой данных
├── services/            # JWT, refresh-токены, утилиты
├── main.go              # Точка входа в приложение и роуты
├── go.mod               # Go-модуль
├── docker-compose.yml   # Конфигурация Docker Compose
└── README.md            # Документация проекта
```

## База данных

В проекте используется PostgreSQL. Для хранения `refresh` токенов реализована таблица `refresh_tokens`.  
Access токены не хранятся в базе данных по требованиям безопасности.

### Таблица `refresh_tokens`

```sql
CREATE TABLE refresh_tokens (
    id UUID PRIMARY KEY,                  -- Уникальный идентификатор refresh-токена
    user_id UUID NOT NULL,                -- GUID пользователя
    token_hash TEXT NOT NULL,             -- bcrypt-хэш refresh-токена
    user_agent TEXT NOT NULL,             -- User-Agent клиента
    ip_address TEXT NOT NULL,             -- IP-адрес клиента
    expires_at TIMESTAMP NOT NULL,        -- Время истечения срока действия токена
    created_at TIMESTAMP NOT NULL,        -- Время создания записи
    revoked_at TIMESTAMP NULL             -- Время отзыва токена (может быть NULL)
);
```

## Эндпоинты

```http
POST   /auth/generate                   # Получение пары access/refresh токенов
POST   /auth/refresh                    # Обновление пары токенов
POST   /auth/revoke                     # Деавторизация пользователя
GET    /auth/me                         # Получение GUID текущего пользователя (access required)
GET    /swagger/                        # Документация swagger
```
## Запуск проекта

### 1. Склонируйте репозиторий

```bash
git clone https://github.com/A737580/authorization_go.git
cd authorization_go
```
### 2. Запуск через Docker Compose
```bash
docker-compose -f docker-compose.yml up -d
```
