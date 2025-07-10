// @title           Auth Service API
// @version         1.0
// @description     This is a sample authentication service API.
// @termsOfService  http://swagger.io/terms/

// @contact.name   API Support
// @contact.url    http://www.swagger.io/support
// @contact.email  support@swagger.io

// @license.name  Apache 2.0
// @license.url   http://www.apache.org/licenses/LICENSE-2.0.html

// @host      localhost:8080
// @BasePath  /

// @securityDefinitions.apikey BearerAuth
// @in header
// @name Authorization
// @description Type "Bearer" then a space and your JWT token.
package main

import (
	"database/sql"
	"log"
	"net/http"
	"os"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/joho/godotenv"

	"github.com/golang-migrate/migrate/v4"
	_ "github.com/golang-migrate/migrate/v4/database/postgres"
	_ "github.com/golang-migrate/migrate/v4/source/file"

	_ "github.com/lib/pq"

	_ "auth-service-go/docs"

	swaggerFiles "github.com/swaggo/files"
	ginSwagger "github.com/swaggo/gin-swagger"
)

var db *sql.DB

var JWTSecret string
var webhookURL string

var tokenRepo TokenRepository
var authService AuthService
var authHandlers *AuthHandlers

func main() {
	// Загружаем переменные окружения из файла .env.
	err := godotenv.Load()
	if err != nil {
		log.Printf("Warning: Could not load .env file (this might be expected in containerized environments): %v", err)
	}

	// Получаем переменных окружения.
	JWTSecret = os.Getenv("JWT_SECRET")
	if JWTSecret == "" {
		log.Fatalf("Error: JWT_SECRET environment variable not set. This is required.")
	}
	log.Println("JWT_SECRET loaded successfully.")

	webhookURL = os.Getenv("WEBHOOK_NOTIFICATION_URL")
	if webhookURL == "" {
		log.Printf("Error: WEBHOOK_NOTIFICATION_URL environment variable not set.")
	}

	// Инициализируем соединение с базой данных и применяем миграции.
	const maxRetries = 10
	const retryDelay = 5 * time.Second

	for i := 0; i < maxRetries; i++ {
		log.Printf("Attempt %d of %d: Initializing database and applying migrations...", i+1, maxRetries)

		if os.Getenv("DATABASE_URL") == "" {
			log.Printf("DATABASE_URL not found in environment. Retrying in %v...", retryDelay)
			time.Sleep(retryDelay)
			continue
		}

		err = initDB()
		if err == nil {
			err = applyMigrations()
			if err == nil || err == migrate.ErrNoChange {
				log.Println("Database initialized and migrations applied successfully.")
				break
			}
			log.Printf("Failed to apply migrations: %v. Retrying in %v...", err, retryDelay)
		} else {
			log.Printf("Failed to connect to database: %v. Retrying in %v...", err, retryDelay)
		}
		time.Sleep(retryDelay)
	}

	if err != nil && err != migrate.ErrNoChange {
		log.Fatalf("Failed to initialize database and apply migrations after multiple retries: %v", err)
	}

	// Гарантируем закрытие соединения с БД при завершении работы приложения.
	defer func() {
		if db != nil {
			db.Close()
			log.Println("Database connection closed.")
		}
	}()

	// 4. Инициализируем TokenRepository, AuthService и AuthHandlers
	tokenRepo = NewPostgresTokenRepository(db)
	authService = NewAuthService(tokenRepo, JWTSecret, webhookURL)
	authHandlers = NewAuthHandlers(authService)
	log.Println("TokenRepository, AuthService, and AuthHandlers initialized.")

	router := gin.Default()

	// Роуты
	router.GET("/", func(c *gin.Context) {
		if db == nil {
			c.JSON(http.StatusInternalServerError, gin.H{
				"message": "Auth service is running, but database connection is not established!",
			})
			return
		}
		err := db.Ping()
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{
				"message": "Auth service is running, but database connection failed!",
				"error":   err.Error(),
			})
			return
		}
		c.JSON(http.StatusOK, gin.H{
			"message": "Auth service is running and database connected successfully!",
		})
	})

	router.GET("/swagger/*any", ginSwagger.WrapHandler(swaggerFiles.Handler))
	router.POST("/auth/generate", authHandlers.GenerateTokensHandler)
	router.POST("/auth/refresh", authHandlers.RefreshTokensHandler)
	router.POST("/auth/revoke", authHandlers.RevokeUserTokensHandler)

	authorized := router.Group("/")
	authorized.Use(AuthMiddleware(authService))
	{
		authorized.GET("/user/me", authHandlers.GetCurrentUserGUIDHandler)
	}

	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
		log.Printf("PORT not set in .env or environment, defaulting to %s", port)
	}

	log.Printf("Server starting on port %s...", port)
	if err := router.Run(":" + port); err != nil {
		log.Fatalf("Failed to run server: %v", err)
	}
}

func initDB() error {
	connStr := os.Getenv("DATABASE_URL")
	if connStr == "" {
		return &missingConfigError{"DATABASE_URL"}
	}

	if db != nil {
		db.Close()
	}

	var err error
	db, err = sql.Open("postgres", connStr)
	if err != nil {
		log.Printf("Error opening database connection: %v", err)
		return err
	}

	db.SetConnMaxLifetime(5 * time.Minute)
	db.SetMaxOpenConns(10)
	db.SetMaxIdleConns(5)

	err = db.Ping()
	if err != nil {
		log.Printf("Error pinging database: %v", err)
		return err
	}

	log.Println("Database connection established successfully.")
	return nil
}

func applyMigrations() error {
	connStr := os.Getenv("DATABASE_URL")
	if connStr == "" {
		return &missingConfigError{"DATABASE_URL"}
	}

	migrationsPath := "file://./migrations"
	log.Printf("Applying migrations from path: %s to database: %s", migrationsPath, connStr)

	m, err := migrate.New(
		migrationsPath,
		connStr,
	)
	if err != nil {
		log.Printf("Failed to create migrate instance: %v", err)
		return err
	}
	defer m.Close()

	err = m.Up()
	if err != nil && err != migrate.ErrNoChange {
		log.Printf("Migration failed: %v", err)
		return err
	}
	if err == migrate.ErrNoChange {
		log.Println("No new migrations to apply.")
	} else {
		log.Println("Migrations applied successfully.")
	}
	return nil
}

type missingConfigError struct {
	key string
}

func (e *missingConfigError) Error() string {
	return "Missing required environment variable: " + e.key
}
