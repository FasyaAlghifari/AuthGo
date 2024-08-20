package controllers

import (
	"encoding/json"
	"net/http"
	"project-gin/initializers"
	"project-gin/models"
	"strconv"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt"
	"golang.org/x/crypto/bcrypt"
)

func Register(c *gin.Context) {
	var user models.User
	err := json.NewDecoder(c.Request.Body).Decode(&user)
	if err != nil {
		c.JSON(400, err.Error())
		return
	}

	// Check if user already exists
	var existingUser models.User
	initializers.DB.Where("username = ?", user.Username).First(&existingUser)
	if existingUser.ID != 0 {
		c.JSON(400, "Username already taken")
		return
	}

	// Check if email already exists
	initializers.DB.Where("email = ?", user.Email).First(&existingUser)
	if existingUser.ID != 0 {
		c.JSON(400, "Email already taken")
		return
	}

	// Hash password
	hash, err := bcrypt.GenerateFromPassword([]byte(user.Password), 12)
	if err != nil {
		c.JSON(500, err.Error())
		return
	}

	user.Password = string(hash)

	// Create new user
	initializers.DB.Create(&user)

	c.JSON(201, user)
}

func Login(c *gin.Context) {
	var user models.User
	if err := c.BindJSON(&user); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request"})
		return
	}

	var foundUser models.User
	initializers.DB.Where("email = ?", user.Email).First(&foundUser)

	if foundUser.ID == 0 {
		c.JSON(http.StatusNotFound, gin.H{"error": "User not found"})
		return
	}

	if err := bcrypt.CompareHashAndPassword([]byte(foundUser.Password), []byte(user.Password)); err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid password"})
		return
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"email": foundUser.Email,
		"exp":   time.Now().Add(time.Hour * 24).Unix(),
	})

	tokenString, err := token.SignedString([]byte(initializers.Config.JWTSecret))
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Could not sign token"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"token": tokenString})
}

// Dummy data pengguna
var users = map[int]string{
	1: "admin",
	2: "user",
}

func UserRoles(c *gin.Context) {
	// Endpoint untuk mendapatkan peran pengguna berdasarkan ID
	userID, ok := c.GetQuery("id")
	if !ok {
		c.JSON(http.StatusBadRequest, gin.H{"error": "User ID is required"})
		return
	}

	// Konversi ID ke integer
	id, err := strconv.Atoi(userID)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid User ID"})
		return
	}

	// Temukan peran berdasarkan ID
	role, exists := users[id]
	if !exists {
		c.JSON(http.StatusNotFound, gin.H{"error": "User not found"})
		return
	}

	// Kirimkan data peran pengguna
	c.JSON(http.StatusOK, gin.H{"role": role})

}