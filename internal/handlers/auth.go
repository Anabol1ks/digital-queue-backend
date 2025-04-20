package handlers

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"net/http"
	"os"
	"strconv"
	"time"

	"test_hack/internal/models"
	"test_hack/internal/response"
	"test_hack/internal/storage"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
	"github.com/wneessen/go-mail"
	"golang.org/x/crypto/bcrypt"
)

var (
	AccessSecret  = []byte(os.Getenv("JWT_ACCESS_SECRET"))
	refreshSecret = []byte(os.Getenv("JWT_REFRESH_SECRET"))
)

type RegisterRequest struct {
	Name     string `json:"name" binding:"required"`
	Surname  string `json:"surname" binding:"required"`
	Email    string `json:"email" binding:"required,email"`
	Password string `json:"password" binding:"required,min=6"`
}

type LoginRequest struct {
	Email    string `json:"email" binding:"required,email"`
	Password string `json:"password" binding:"required"`
}

// @Summary		Регистрация пользователя
// @Description	Регистрация нового пользователя
// @Tags			auth
// @Accept			json
// @Produce		json
// @Param			user	body		RegisterRequest				true	"Данные пользователя"
// @Success		201		{object}	response.SuccessResponse	"Успешная регистрация"
// @Failure		400		{object}	response.ErrorResponse		"Ошибка валидации (VALIDATION_ERROR) или пользователь уже существует (EMAIL_EXISTS)"
// @Failure		500		{object}	response.ErrorResponse		"Ошибка сервера (PASSWORD_HASH_ERROR, DB_ERROR)"
// @Router			/auth/register [post]
func Register(c *gin.Context) {
	var req RegisterRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, response.ErrorResponse{
			Code:    "VALIDATION_ERROR",
			Message: "Ошибка валидации данных",
			Details: err.Error(),
		})
		return
	}

	var existingUser models.User
	if err := storage.DB.Where("email = ?", req.Email).First(&existingUser).Error; err == nil {
		c.JSON(http.StatusBadRequest, response.ErrorResponse{
			Code:    "EMAIL_EXISTS",
			Message: "Пользователь с таким email уже существует",
		})
		return
	}

	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(req.Password), bcrypt.DefaultCost)
	if err != nil {
		c.JSON(http.StatusInternalServerError, response.ErrorResponse{
			Code:    "PASSWORD_HASH_ERROR",
			Message: "Ошибка при хешировании пароля",
		})
		return
	}

	user := models.User{
		Name:         req.Name,
		Surname:      req.Surname,
		Email:        req.Email,
		PasswordHash: string(hashedPassword),
	}

	if err := storage.DB.Create(&user).Error; err != nil {
		c.JSON(http.StatusInternalServerError, response.ErrorResponse{
			Code:    "DB_ERROR",
			Message: "Ошибка при создании пользователя",
		})
		return
	}

	c.JSON(http.StatusCreated, response.SuccessResponse{
		Message: "Пользователь успешно зарегистрирован",
	})
}

// @Summary		Авторизация пользователя
// @Description	Авторизация пользователя и получение токенов
// @Tags			auth
// @Accept			json
// @Produce		json
// @Param			user	body		LoginRequest			true	"Данные для авторизации"
// @Success		200		{object}	response.TokenResponse	"Успешная авторизация"
// @Failure		400		{object}	response.ErrorResponse	"Ошибка валидации данных (VALIDATION_ERROR)"
// @Failure		401		{object}	response.ErrorResponse	"Неверные учетные данные (INVALID_CREDENTIALS)"
// @Failure		500		{object}	response.ErrorResponse	"Ошибка сервера (TOKEN_GENERATION_ERROR)"
// @Router			/auth/login [post]
func Login(c *gin.Context) {
	var req LoginRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, response.ErrorResponse{
			Code:    "VALIDATION_ERROR",
			Message: "Ошибка валидации данных",
			Details: err.Error(),
		})
		return
	}

	var user models.User
	if err := storage.DB.Where("email = ?", req.Email).First(&user).Error; err != nil {
		c.JSON(http.StatusUnauthorized, response.ErrorResponse{
			Code:    "INVALID_CREDENTIALS",
			Message: "Неверный email или пароль",
		})
		return
	}

	if err := bcrypt.CompareHashAndPassword([]byte(user.PasswordHash), []byte(req.Password)); err != nil {
		c.JSON(http.StatusUnauthorized, response.ErrorResponse{
			Code:    "INVALID_CREDENTIALS",
			Message: "Неверный email или пароль",
		})
		return
	}

	accessToken, err := generateToken(user.ID, time.Minute*15, AccessSecret)
	if err != nil {
		c.JSON(http.StatusInternalServerError, response.ErrorResponse{
			Code:    "TOKEN_GENERATION_ERROR",
			Message: "Ошибка при генерации access токена",
		})
		return
	}

	refreshToken, err := generateToken(user.ID, time.Hour*24*7, refreshSecret)
	if err != nil {
		c.JSON(http.StatusInternalServerError, response.ErrorResponse{
			Code:    "TOKEN_GENERATION_ERROR",
			Message: "Ошибка при генерации refresh токена",
		})
		return
	}

	c.JSON(http.StatusOK, response.TokenResponse{
		AccessToken:  accessToken,
		RefreshToken: refreshToken,
	})
}

func generateToken(userID uint, duration time.Duration, secret []byte) (string, error) {
	claims := jwt.MapClaims{
		"user_id": userID,
		"exp":     time.Now().Add(duration).Unix(),
		"iat":     time.Now().Unix(),
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString(secret)
}

type RefreshTokenRequest struct {
	RefreshToken string `json:"refresh_token" binding:"required"`
}

// @Summary		Обновление access токена
// @Description	Обновление access токена с помощью refresh токена
// @Tags			auth
// @Accept			json
// @Produce		json
// @Param			refresh_token	body		RefreshTokenRequest		true	"Refresh токен"
// @Success		200				{object}	response.TokenResponse	"Успешное обновление access токена"
// @Failure		400				{object}	response.ErrorResponse	"Ошибка валидации данных (VALIDATION_ERROR)"
// @Failure		401				{object}	response.ErrorResponse	"Неверный или просроченный refresh токен (INVALID_REFRESH_TOKEN) или пользователь не найден (USER_NOT_FOUND)"
// @Failure		500				{object}	response.ErrorResponse	"Ошибка сервера (TOKEN_GENERATION_ERROR)"
// @Router			/auth/refresh [post]
func RefreshToken(c *gin.Context) {
	var req RefreshTokenRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, response.ErrorResponse{
			Code:    "VALIDATION_ERROR",
			Message: "Ошибка валидации данных",
			Details: err.Error(),
		})
		return
	}

	token, err := jwt.Parse(req.RefreshToken, func(token *jwt.Token) (interface{}, error) {
		return refreshSecret, nil
	})
	if err != nil || !token.Valid {
		c.JSON(http.StatusUnauthorized, response.ErrorResponse{
			Code:    "INVALID_REFRESH_TOKEN",
			Message: "Неверный или просроченный refresh токен",
		})
		return
	}

	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok || !token.Valid {
		c.JSON(http.StatusUnauthorized, response.ErrorResponse{
			Code:    "INVALID_REFRESH_TOKEN",
			Message: "Неверный или просроченный refresh токен",
		})
		return
	}

	userIDFloat, ok := claims["user_id"].(float64)
	if !ok {
		c.JSON(http.StatusUnauthorized, response.ErrorResponse{
			Code:    "INVALID_REFRESH_TOKEN",
			Message: "Неверный или просроченный refresh токен",
		})
		return
	}

	userID := uint(userIDFloat)

	var user models.User
	if err := storage.DB.First(&user, userID).Error; err != nil {
		c.JSON(http.StatusUnauthorized, response.ErrorResponse{
			Code:    "USER_NOT_FOUND",
			Message: "Пользователь не найден",
		})
		return
	}

	newAccessToken, err := generateToken(user.ID, time.Minute*15, AccessSecret)
	if err != nil {
		c.JSON(http.StatusInternalServerError, response.ErrorResponse{
			Code:    "TOKEN_GENERATION_ERROR",
			Message: "Ошибка при генерации access токена",
		})
		return
	}

	newRefreshToken, err := generateToken(userID, time.Hour*24*7, refreshSecret)
	if err != nil {
		c.JSON(http.StatusInternalServerError, response.ErrorResponse{
			Code:    "TOKEN_GENERATION_ERROR",
			Message: "Ошибка при генерации нового refresh токена",
		})
		return
	}

	c.JSON(http.StatusOK, response.TokenResponse{
		AccessToken:  newAccessToken,
		RefreshToken: newRefreshToken,
	})
}

// GetMyProfileHandler godoc
// @Summary		Получение данных пользователя
// @Description	Получение данных пользователя по токену
// @Tags			profile
// @Accept			json
// @Produce		json
// @Security		BearerAuth
// @Success		200	{object}	response.ProfileResponse	"Успешное получение данных пользователя"
// @Failure		401	{object}	response.ErrorResponse	"Ошибка авторизации (UNAUTHORIZED)"
// @Failure		500	{object}	response.ErrorResponse	"Ошибка сервера (DB_ERROR)"
// @Router			/profile [get]
func GetMyProfileHandler(c *gin.Context) {
	userID := c.GetUint("userID")
	if userID == 0 {
		c.JSON(http.StatusUnauthorized, response.ErrorResponse{
			Code:    "UNAUTHORIZED",
			Message: "Ошибка авторизации",
		})
		return
	}
	var user models.User
	if err := storage.DB.First(&user, userID).Error; err != nil {
		c.JSON(http.StatusInternalServerError, response.ErrorResponse{
			Code:    "DB_ERROR",
			Message: "Ошибка при получении данных пользователя",
			Details: err.Error(),
		})
		return
	}
	c.JSON(http.StatusOK, response.ProfileResponse{
		ID:      user.ID,
		Name:    user.Name,
		Surname: user.Surname,
		Email:   user.Email,
	})
}

type ForgotPasswordRequest struct {
	Email string `json:"email" binding:"required,email"`
}

// ForgotPassword godoc
// @Summary      Запрос на сброс пароля
// @Description  Отправляет письмо с ссылкой для сброса пароля на указанный email
// @Tags         auth
// @Accept       json
// @Produce      json
// @Param        email  body  ForgotPasswordRequest  true  "Email пользователя"
// @Success      200    {object}  response.SuccessResponse  "Письмо отправлено"
// @Failure      400    {object}  response.ErrorResponse    "Ошибка валидации данных"
// @Failure      404    {object}  response.ErrorResponse    "Пользователь не найден"
// @Failure      500    {object}  response.ErrorResponse    "Ошибка сервера"
// @Router       /auth/forgot-password [post]
func ForgotPassword(c *gin.Context) {
	var req ForgotPasswordRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, response.ErrorResponse{
			Code:    "VALIDATION_ERROR",
			Message: "Ошибка валидации данных",
			Details: err.Error(),
		})
		return
	}

	var user models.User
	if err := storage.DB.Where("email = ?", req.Email).First(&user).Error; err != nil {
		c.JSON(http.StatusNotFound, response.ErrorResponse{
			Code:    "USER_NOT_FOUND",
			Message: "Пользователь с таким email не найден",
		})
		return
	}

	// Генерация токена для сброса пароля
	resetToken := make([]byte, 16)
	if _, err := rand.Read(resetToken); err != nil {
		c.JSON(http.StatusInternalServerError, response.ErrorResponse{
			Code:    "TOKEN_GENERATION_ERROR",
			Message: "Ошибка при генерации токена",
		})
		return
	}
	resetTokenHex := hex.EncodeToString(resetToken)

	// Сохранение токена в базе данных
	user.PasswordResetToken = resetTokenHex
	user.PasswordResetExpires = time.Now().Add(1 * time.Hour)
	if err := storage.DB.Save(&user).Error; err != nil {
		c.JSON(http.StatusInternalServerError, response.ErrorResponse{
			Code:    "DB_ERROR",
			Message: "Ошибка при сохранении токена",
		})
		return
	}
	frontendURL := os.Getenv("URL_FRONT")
	// Отправка письма
	resetLink := fmt.Sprintf(frontendURL+"/auth/reset-password?token=%s", resetTokenHex)
	if err := sendResetPasswordEmail(user.Email, resetLink); err != nil {
		c.JSON(http.StatusInternalServerError, response.ErrorResponse{
			Code:    "EMAIL_ERROR",
			Message: "Ошибка при отправке письма",
		})
		return
	}

	c.JSON(http.StatusOK, response.SuccessResponse{
		Message: "Письмо для сброса пароля отправлено",
	})
}

type ResetPasswordRequest struct {
	Token    string `json:"token" binding:"required"`
	Password string `json:"password" binding:"required,min=6"`
}

// ResetPassword godoc
// @Summary      Сброс пароля
// @Description  Сбрасывает пароль пользователя на основе токена из письма
// @Tags         auth
// @Accept       json
// @Produce      json
// @Param        reset_password  body  ResetPasswordRequest  true  "Токен и новый пароль"
// @Success      200    {object}  response.SuccessResponse  "Пароль успешно сброшен"
// @Failure      400    {object}  response.ErrorResponse    "Ошибка валидации данных"
// @Failure      401    {object}  response.ErrorResponse    "Неверный или истекший токен"
// @Failure      500    {object}  response.ErrorResponse    "Ошибка сервера"
// @Router       /auth/reset-password [post]
func ResetPassword(c *gin.Context) {
	var req ResetPasswordRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, response.ErrorResponse{
			Code:    "VALIDATION_ERROR",
			Message: "Ошибка валидации данных",
			Details: err.Error(),
		})
		return
	}

	var user models.User
	if err := storage.DB.Where("password_reset_token = ?", req.Token).First(&user).Error; err != nil {
		c.JSON(http.StatusUnauthorized, response.ErrorResponse{
			Code:    "INVALID_TOKEN",
			Message: "Неверный или просроченный токен",
		})
		return
	}

	if time.Now().After(user.PasswordResetExpires) {
		c.JSON(http.StatusUnauthorized, response.ErrorResponse{
			Code:    "TOKEN_EXPIRED",
			Message: "Токен истёк",
		})
		return
	}

	// Хеширование нового пароля
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(req.Password), bcrypt.DefaultCost)
	if err != nil {
		c.JSON(http.StatusInternalServerError, response.ErrorResponse{
			Code:    "PASSWORD_HASH_ERROR",
			Message: "Ошибка при хешировании пароля",
		})
		return
	}

	user.PasswordHash = string(hashedPassword)
	user.PasswordResetToken = ""
	user.PasswordResetExpires = time.Time{}
	if err := storage.DB.Save(&user).Error; err != nil {
		c.JSON(http.StatusInternalServerError, response.ErrorResponse{
			Code:    "DB_ERROR",
			Message: "Ошибка при сохранении нового пароля",
		})
		return
	}

	c.JSON(http.StatusOK, response.SuccessResponse{
		Message: "Пароль успешно сброшен",
	})
}

func sendResetPasswordEmail(email, resetLink string) error {
	m := mail.NewMsg()
	m.From(os.Getenv("SMTP_USERNAME"))
	m.To(email)
	m.Subject("Сброс пароля")
	m.SetBodyString(mail.TypeTextHTML, fmt.Sprintf(`
        <html>
        <body style="font-family: Arial, sans-serif; background-color: #f9f9f9; margin: 0; padding: 0;">
            <table align="center" border="0" cellpadding="0" cellspacing="0" width="600" style="border-collapse: collapse; background-color: #ffffff; border: 1px solid #dddddd; margin-top: 20px;">
                <tr>
                    <td align="center" style="padding: 20px 0; background-color: #00004B; color: #ffffff; font-size: 24px; font-weight: bold;">
                        Сброс пароля
                    </td>
                </tr>
                <tr>
                    <td style="padding: 20px; color: #333333; font-size: 16px; line-height: 1.5;">
                        <p>Здравствуйте</p>
                        <p>Вы запросили сброс пароля для вашей учетной записи. Чтобы сбросить пароль, нажмите на кнопку ниже:</p>
                        <p style="text-align: center;">
                            <a href="%s" style="display: inline-block; padding: 10px 20px; background-color: #00004B; color: #ffffff; text-decoration: none; border-radius: 5px; font-size: 16px;">Сбросить пароль</a>
                        </p>
                        <p>Если вы не запрашивали сброс пароля, просто проигнорируйте это письмо.</p>
                        <p>С уважением,<br>Команда поддержки</p>
                    </td>
                </tr>
                <tr>
                    <td align="center" style="padding: 10px; background-color: #f1f1f1; color: #666666; font-size: 12px;">
                        © 2025 Онлайн очередь. Все права защищены.
                    </td>
                </tr>
            </table>
        </body>
        </html>
    `, resetLink))

	client, err := mail.NewClient(os.Getenv("SMTP_HOST"),
		mail.WithPort(getEnvAsInt("SMTP_PORT", 587)),
		mail.WithSMTPAuth(mail.SMTPAuthPlain),
		mail.WithUsername(os.Getenv("SMTP_USERNAME")),
		mail.WithPassword(os.Getenv("SMTP_PASSWORD")),
	)
	if err != nil {
		return err
	}

	return client.DialAndSend(m)
}

// getEnvAsInt - вспомогательная функция для чтения числовых переменных окружения
func getEnvAsInt(key string, defaultValue int) int {
	valueStr := os.Getenv(key)
	if value, err := strconv.Atoi(valueStr); err == nil {
		return value
	}
	return defaultValue
}
