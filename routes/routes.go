package routes

import (
	"github.com/cagataygedik/ecommerce/controllers"
	"github.com/gin-gonic/gin"
)

func UserRoutes(incomingRoutes *gin.Engine) {
	incomingRoutes.POST("/users/signup", controllers.Signup())
	incomingRoutes.POST("/users/login", controllers.Login())
	incomingRoutes.POST("/admin/addproduct", controllers.ProductViewerAdmin())
	incomingRoutes.GET("/users/prodcuctview", controllers.SearchProduct())
	incomingRoutes.GET("/user/search", controllers.SearchProductByQuery())
}
