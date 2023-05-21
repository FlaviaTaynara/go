package main

import (
	"fmt"
	"log"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/dgrijalva/jwt-go"
	"github.com/gin-gonic/gin"
	"golang.org/x/crypto/bcrypt"
)

type JWTClaims struct {
	UserEmail string `json:"email"`
	jwt.StandardClaims
}


type User struct {
	Name          string  `json:"name"`
}

type Login struct {
	Email    string `json:"email"`
	Password string `json:"password"`
}

type RegisterData struct {
	Name                  string
	Email                 string
	Password              string
	Errors                map[string]string
}

type ValidationError struct {
	Errors []string
}

type LoginUser struct {
	Email    string
	Password string
}

var userStore = map[string]LoginUser{
	"user@example.com": {
		Email:    "user@example.com",
		Password: "password123",
	},
	// Add more users as needed
}

func getUserByEmail(email string) *LoginUser {
	if user, ok := userStore[email]; ok {
		return &user
	}
	return nil
}


func (e *ValidationError) Error() string {
	return strings.Join(e.Errors, ", ")
}


func main() {
	r := gin.New()

	r.LoadHTMLGlob("templates/*")

	r.Use(gin.Logger())
	r.Use(gin.Recovery())

	r.GET("/register", renderRegisterForm)
	r.POST("/register", handleRegisterForm)
	r.POST("/login", handleLogin)
	r.GET("/login", renderLogin)
	r.GET("/dashboard", renderDashboard)

	if err := r.Run(":8080"); err != nil {
		log.Fatal(err)
	}
}

func createToken(email string) string {
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, &JWTClaims{
		UserEmail: email,
		StandardClaims: jwt.StandardClaims{
			ExpiresAt: time.Now().Add(24 * time.Hour).Unix(), // Token expiration time
		},
	})

	tokenString, _ := token.SignedString([]byte("your-secret-key")) // Replace with your secret key

	return tokenString
}

func renderDashboard(c *gin.Context) {
	// Get the token from the request cookie
	token, err := c.Cookie("token")
	if err != nil {
		c.Redirect(http.StatusSeeOther, "/login")
		return
	}

	// Verify and parse the token
	parsedToken, err := jwt.ParseWithClaims(token, &JWTClaims{}, func(token *jwt.Token) (interface{}, error) {
		// Provide the same secret key used during token generation
		return []byte("your-secret-key"), nil
	})

	if err != nil || !parsedToken.Valid {
		c.Redirect(http.StatusSeeOther, "/login")
		return
	}

	// Token is valid, proceed to render the dashboard
	c.HTML(http.StatusOK, "dashboard.html", nil)
}


func renderLogin(c *gin.Context) {
	c.HTML(http.StatusOK, "login.html", nil)

}

func authenticateUser(email, password string) (bool, error) {
	userData := getUserByEmail(email)

	if userData == nil {
		return false, fmt.Errorf("user not found")
	}

	err := bcrypt.CompareHashAndPassword([]byte(userData.Password), []byte(password))
	if err != nil {
		return false, err
	}

	return true, nil
}


func authenticateMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		// Get the token from the request cookie
		token, err := c.Cookie("token")
		if err != nil {
			c.Redirect(http.StatusSeeOther, "/login")
			c.Abort()
			return
		}

		// Verify and parse the token
		parsedToken, err := jwt.ParseWithClaims(token, &JWTClaims{}, func(token *jwt.Token) (interface{}, error) {
			// Provide the same secret key used during token generation
			return []byte("your-secret-key"), nil
		})

		if err != nil || !parsedToken.Valid {
			c.Redirect(http.StatusSeeOther, "/login")
			c.Abort()
			return
		}

		// Token is valid, continue to the next middleware or handler
		c.Next()
	}
}


func handleLogin(c *gin.Context) {
	email := c.PostForm("email")
	password := c.PostForm("password")

	success, err := authenticateUser(email, password)

	if err != nil || !success {
		c.HTML(http.StatusOK, "login.html", gin.H{
			"error": "Invalid email or password",
		})
		return
	}

	tokenString := createToken(email)

	// Set the token as a cookie
	c.SetCookie("token", tokenString, int(time.Hour*24), "/", "", false, true)

	// Redirect to the dashboard
	c.Redirect(http.StatusSeeOther, "/dashboard")
}






func renderRegisterForm(c *gin.Context) {
	c.HTML(http.StatusOK, "register.html", nil)
}

func handleRegisterForm(c *gin.Context) {
	data := RegisterData{
		Name:                  c.PostForm("name"),
		Email:                 c.PostForm("email"),
		Password:              c.PostForm("password"),
		
	}

	validateRegisterData(&data)

	if len(data.Errors) > 0 {
		c.HTML(http.StatusOK, "register.html", gin.H{
			"data": data,
		})
		return
	}

	processRegistration(&data)

	c.Redirect(http.StatusSeeOther, "/login")
}

func validateRegisterData(data *RegisterData) {
    validationErr := make(map[string]string) // Initialize validationErr as an empty map
    if data.Name == "" {
        validationErr["Name"] = "Nome obrigatório"
    }
    if data.Email == "" {
        validationErr["Email"] = "Email obrigatório"
    }
    if data.Password == "" {
        validationErr["Password"] = "Senha obrigatória"
    } else {
        passwordRegex := regexp.MustCompile(`(\d)`)
        if !passwordRegex.MatchString(data.Password) {
            validationErr["Password"] = "Deve conter ao menos 1 número"
        }
        passwordRegex = regexp.MustCompile(`[a-z]`)
        if !passwordRegex.MatchString(data.Password) {
            validationErr["Password"] = "Deve conter ao menos 1 letra minúscula"
        }
        passwordRegex = regexp.MustCompile(`[A-Z]`)
        if !passwordRegex.MatchString(data.Password) {
            validationErr["Password"] = "Deve conter ao menos 1 letra maiúscula"
        }
        passwordRegex = regexp.MustCompile(`(\W|_)`)
        if !passwordRegex.MatchString(data.Password) {
            validationErr["Password"] = "Deve conter no mínimo 1 caracter especial"
        }
        passwordRegex = regexp.MustCompile(`.{6,}`)
        if !passwordRegex.MatchString(data.Password) {
            validationErr["Password"] = "Deve conter no mínimo 6 caracteres"
        }
    }
    data.Errors = validationErr
}


func processRegistration(data *RegisterData) {
	// Verificar se há erros de validação
	if len(data.Errors) > 0 {
		// Exibir mensagens de erro
		fmt.Println("Erro de validação:")
		for field, message := range data.Errors {
			fmt.Printf("%s: %s\n", field, message)
		}
		return
	}

fmt.Println("Registro do usuário processado com sucesso!")
fmt.Printf("Nome: %s\n", data.Name)
fmt.Printf("Email: %s\n", data.Email)
fmt.Printf("Senha: %s\n", data.Password)
}
