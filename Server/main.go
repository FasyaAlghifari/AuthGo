package main

import (
	"net/http"
	"project-gin/controllers"
	"project-gin/initializers"
	"project-gin/middleware"
	"strconv"
	"time"

	"github.com/gin-contrib/cors"
	"github.com/gin-gonic/gin"
)

func init() {
	initializers.LoadEnvVariables()
	initializers.ConnectToDB()
	initializers.LoadConfig()
}

var users = map[int]string{
	1: "admin",
	2: "user",
}

func main() {
	r := gin.Default()

	// Enable CORS with custom configuration
	r.Use(cors.New(cors.Config{
		AllowOrigins:     []string{"http://localhost:8000"},
		AllowMethods:     []string{"GET", "POST", "PUT", "DELETE", "OPTIONS"},
		AllowHeaders:     []string{"Origin", "Content-Type", "Authorization"},
		ExposeHeaders:    []string{"Content-Length"},
		AllowCredentials: true,
		MaxAge:           12 * time.Hour,
	}))

	// Routes for User
	r.POST("/login", controllers.Login)
	r.POST("/register", controllers.Register)
	r.GET("/user-role", func(c *gin.Context) {
		// Mendapatkan ID pengguna dari query parameter
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
	})

	// Add a route for "/"
	r.GET("/", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{
			"message": "Welcome to the IT Security App",
		})
	})

	// Group routes that require authentication
	protected := r.Group("/sag")
	protected.Use(middleware.AuthMiddleware())
	{
		// Routes for SAG
		protected.GET("/", controllers.SagIndex)
		protected.POST("/", controllers.CreateSag)
		protected.GET("/:id", controllers.PostsShow)
		protected.PUT("/:id", controllers.PostsUpdate)
		protected.DELETE("/:id", controllers.PostsDelete)
		protected.GET("/export", controllers.CreateExcelSag)
		protected.POST("/upload", controllers.ImportExcelSag)
	}

	// Other routes that do not require authentication
	r.GET("/updateAll", controllers.UpdateAllExcelSheets)
	r.GET("/exportAll", controllers.ExportAllSheets)

	r.Run(":8080")
}