package jwt_manager

import (
	"fmt"
	"time"

	"github.com/golang-jwt/jwt"
)

type JWTManager struct {
	secretKey     string
	tokenDuration time.Duration
}

type UserClaims struct {
	jwt.StandardClaims
	UserId       uint64 `json:"userId"`
	Subscription string `json:"subscription,omitempty"` // Поле опционально
	EndDate      string `json:"endDate,omitempty"`      // Поле опционально
}

func NewJWTManager(secretKey string, tokenDuration time.Duration) *JWTManager {
	return &JWTManager{secretKey, tokenDuration}
}

func (manager *JWTManager) GenerateSimple(userId uint64) (string, error) {
	claims := UserClaims{
		StandardClaims: jwt.StandardClaims{
			ExpiresAt: time.Now().Add(manager.tokenDuration).Unix(),
		},
		UserId: userId,
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString([]byte(manager.secretKey))
}

func (manager *JWTManager) GenerateWithSubscription(userId uint64, subscription string, endDate string) (string, error) {
	claims := UserClaims{
		StandardClaims: jwt.StandardClaims{
			ExpiresAt: time.Now().Add(manager.tokenDuration).Unix(),
		},
		UserId:       userId,
		Subscription: subscription,
		EndDate:      endDate,
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString([]byte(manager.secretKey))
}

func (manager *JWTManager) VerifySimple(accessToken string) (*uint64, error) {
	token, err := jwt.ParseWithClaims(
		accessToken,
		&UserClaims{},
		func(token *jwt.Token) (interface{}, error) {
			_, ok := token.Method.(*jwt.SigningMethodHMAC)
			if !ok {
				return nil, fmt.Errorf("unexpected token signing method")
			}
			return []byte(manager.secretKey), nil
		},
	)

	if err != nil {
		return nil, fmt.Errorf("invalid token: %w", err)
	}

	claims, ok := token.Claims.(*UserClaims)
	if !ok || claims.Subscription != "" || claims.EndDate != "" {
		return nil, fmt.Errorf("invalid token claims or extra fields present")
	}

	return &claims.UserId, nil
}

func (manager *JWTManager) VerifyWithSubscription(accessToken string) (*uint64, *string, *string, error) {
	token, err := jwt.ParseWithClaims(
		accessToken,
		&UserClaims{},
		func(token *jwt.Token) (interface{}, error) {
			_, ok := token.Method.(*jwt.SigningMethodHMAC)
			if !ok {
				return nil, fmt.Errorf("unexpected token signing method")
			}
			return []byte(manager.secretKey), nil
		},
	)

	if err != nil {
		return nil, nil, nil, fmt.Errorf("invalid token: %w", err)
	}

	claims, ok := token.Claims.(*UserClaims)
	if !ok || claims.Subscription == "" || claims.EndDate == "" {
		return nil, nil, nil, fmt.Errorf("invalid token claims or missing subscription data")
	}

	return &claims.UserId, &claims.Subscription, &claims.EndDate, nil
}
