package middleware

import (
	"fmt"
	"log"
	"net/http"
	"project-gin/initializers"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt"
)

func AuthMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		tokenString := c.GetHeader("Authorization")
		if tokenString == "" {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Authorization header is required"})
			c.Abort()
			return
		}

		// Log token received
		log.Println("Token received:", tokenString)

		// Check if token starts with "Bearer "
		if len(tokenString) > 7 && tokenString[:7] == "Bearer " {
			tokenString = tokenString[7:]
		} else {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid token format"})
			c.Abort()
			return
		}

		log.Println("JWT Secret:", initializers.Config.JWTSecret)

		token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
			if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
				return nil, fmt.Errorf("metode penandatanganan tidak terduga: %v", token.Header["alg"])
			}
			return []byte(initializers.Config.JWTSecret), nil
		})

		if err != nil || !token.Valid {
			log.Println("Token validation error:", err)
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Token tidak valid"})
			c.Abort()
			return
		}

		c.Next()
	}
}
