package controllers

import (
	"fmt"
	"jwt-auth/dto/request"
	"jwt-auth/dto/response"
	"jwt-auth/initializers"
	"jwt-auth/models"
	"net/http"
	"os"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/go-playground/validator/v10"
	"github.com/golang-jwt/jwt/v5"
	"golang.org/x/crypto/bcrypt"
)

func SignUp(c *gin.Context) {
	var body request.SignUp

	// Get the email and password from the request body
	if err := c.ShouldBindJSON(&body); err != nil {
		for _, e := range err.(validator.ValidationErrors) {
			errorMessage := fmt.Sprintf("Error on field %s, condition %s", e.Field(), e.ActualTag())
			c.JSON(http.StatusBadRequest, gin.H{"error": errorMessage})
			return
		}
	}

	// Hash the password
	hashedPass, err := bcrypt.GenerateFromPassword([]byte(body.Password), 10)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"error": "Failed to hash password",
		})
		return
	}

	// Create the user in the database
	user := models.User{
		Name:     body.Name,
		Email:    body.Email,
		Password: string(hashedPass),
	}

	result := initializers.DB.Create(&user)
	if result.Error != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"error": "Failed to create user",
		})
		return
	}

	resp := response.User{
		ID:    user.ID,
		Name:  user.Name,
		Email: user.Email,
	}

	// Respond
	c.JSON(http.StatusOK, gin.H{
		"data":    resp,
		"message": "User created successfully",
	})
}

func Login(c *gin.Context) {
	var body request.Login
	var user models.User

	// Get the email and password from the request body
	if err := c.ShouldBindJSON(&body); err != nil {
		for _, e := range err.(validator.ValidationErrors) {
			errorMessage := fmt.Sprintf("Error on field %s, condition %s", e.Field(), e.ActualTag())
			c.JSON(http.StatusBadRequest, gin.H{"error": errorMessage})
			return
		}
	}

	// Look up requested user
	// If user not found, return error
	err := initializers.DB.Where("email = ?", body.Email).First(&user).Error
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "Invalid email or password",
		})
		return
	}

	// Compare sent in password with saved user password
	err = bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(body.Password))

	// If they don't match, return error
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "Invalid email or password",
		})
		return
	}

	// Generate a JWT token
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"sub": user.ID,
		"exp": time.Now().Add(time.Hour * 24 * 30).Unix(),
	})

	// Sign and get the complete encoded token as a string using the secret
	tokenString, err := token.SignedString([]byte(os.Getenv("SECRET_KEY")))
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"error": "Failed to create token",
		})
		return
	}

	// Send it back
	c.SetSameSite(http.SameSiteLaxMode)
	c.SetCookie("Authorization", tokenString, 3600*24*30, "", "", false, true)

	c.JSON(http.StatusOK, gin.H{
		"message": "Successfully logged in",
	})
}

func GetUsers(c *gin.Context) {
	var users []models.User

	err := initializers.DB.Find(&users).Error
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"message": "Failed to get data users",
		})
	}

	var resp []response.User
	for _, user := range users {
		userResponse := response.User{
			ID:    user.ID,
			Name:  user.Name,
			Email: user.Email,
		}
		resp = append(resp, userResponse)
	}

	c.JSON(http.StatusOK, gin.H{
		"data": gin.H{
			"users": resp,
		},
		"message": "Success get data users",
	})
}
