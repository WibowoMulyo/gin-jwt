package initializers

import "jwt-auth/models"

func SyncDatabase() {
	DB.AutoMigrate(&models.User{})
}
