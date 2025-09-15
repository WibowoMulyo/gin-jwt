package main

import (
	"jwt-auth/controllers"
	"jwt-auth/initializers"
	"jwt-auth/middlewares"
	"os"

	"github.com/gin-gonic/gin"
)

func init() {
	initializers.LoadEnv()
	initializers.ConnectToDB()
	initializers.SyncDatabase()
}

func main() {
	router := gin.Default()
	router.POST("/signup", controllers.SignUp)
	router.POST("/login", controllers.Login)
	router.GET("/users", middlewares.RequireAuth, controllers.GetUsers)
	router.Run(os.Getenv("PORT"))
}
