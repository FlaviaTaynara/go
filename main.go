package main

import (
	"fmt"
	"net/http"
	"regexp"
	"strings"

	"github.com/gin-gonic/gin"
	// "github.com/go-playground/validator/v10"
)

type Input struct {
	ID    string `json:"id"`
	Label string `json:"label"`
	Type  string `json:"type"`
	Error string `json:"error"`
}

type InputPassword struct {
	Label      string `json:"label"`
	ID         string `json:"id"`
	Placeholder string `json:"placeholder"`
	Register   string `json:"register"`
}

type NavBar struct {
	LogoURL string `json:"logoURL"`
}

type Dashboard struct {
	UserLogged  User    `json:"userLogged"`
	ModalOpen   bool    `json:"modalOpen"`
	ModalEdit   bool    `json:"modalEdit"`
}

type User struct {
	Name          string  `json:"name"`
	CourseModule  string  `json:"course_module"`
	Techs         []Tech  `json:"techs"`
}

type Tech struct {
	ID       string `json:"id"`
	Status   string `json:"status"`
	Title    string `json:"title"`
}

type TechContext struct {
	Techs []Tech
	ModalEdit bool
	Alt       string
	Hab       string
}

type UserContext struct {
	ModalEdit bool
	Alt       string
	Hab       string
}

type Login struct {
	Email    string `json:"email"`
	Password string `json:"password"`
}

type RegisterData struct {
	Name                  string
	Email                 string
	Password              string
	PasswordConfirmation string
	Bio                   string
	Contact               string
	CourseModule          string
	Errors                map[string]string
}

type ValidationError struct {
	Errors []string
}

func (e *ValidationError) Error() string {
	return strings.Join(e.Errors, ", ")
}


func main() {
	r := gin.Default()

	r.LoadHTMLGlob("templates/*")

	r.GET("/register", renderRegisterForm)
	r.POST("/register", handleRegisterForm)
	r.POST("/login", handleLogin)
	r.GET("/login", renderLogin)
	r.GET("/dashboard", renderDashboard)
	
	r.Run(":8080")
}

func renderComponent(c *gin.Context, templateName string, data interface{}) {
  
	c.HTML(http.StatusOK, "dashboard.html", nil)

}

func renderDashboard(c *gin.Context) {
	dashboard := Dashboard{
		UserLogged: User{
			Name:         "John Doe",
			CourseModule: "Module 1",
			Techs: []Tech{
				{
					ID:     "1",
					Status: "Beginner",
					Title:  "React",
				},
				{
					ID:     "2",
					Status: "Intermediate",
					Title:  "Golang",
				},
			},
		},
		ModalOpen: true,
		ModalEdit: false,
	}

	renderComponent(c, "dashboard.html", dashboard)
}

func renderLogin(c *gin.Context) {
	c.HTML(http.StatusOK, "login.html", nil)

	// Renderizar o componente Login usando o template "login.html"
}

func handleLogin(c *gin.Context) {
	var login Login
	if err := c.ShouldBind(&login); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// Lógica de autenticação do usuário

	// Redirecionar para a página de Dashboard após o login bem-sucedido

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

	// Validate form data
	validateRegisterData(&data)

	if len(data.Errors) > 0 {
		c.HTML(http.StatusOK, "register.html", gin.H{
			"data": data,
		})
		return
	}

	// Process user registration
	processRegistration(&data)

	c.Redirect(http.StatusSeeOther, "/login")
}

func validateRegisterData(data *RegisterData) {
	var validationErr *ValidationError
	if data.Name == "" {
		validationErr.Errors = append(validationErr.Errors, "Nome obrigatório") 
	}

	if data.Email == "" {
		validationErr.Errors = append(validationErr.Errors, "Email obrigatório") 
	}

	if data.Password == "" {
		validationErr.Errors = append(validationErr.Errors, "Senha obrigatória")
	} else {
		passwordRegex := regexp.MustCompile(`(\d)`)
		if !passwordRegex.MatchString(data.Password) {
			validationErr.Errors = append(validationErr.Errors, "Deve conter ao menos 1 número")
		}

		passwordRegex = regexp.MustCompile(`[a-z]`)
		if !passwordRegex.MatchString(data.Password) {
			validationErr.Errors = append(validationErr.Errors, "Deve conter ao menos 1 letra minúscula")
		}

		passwordRegex = regexp.MustCompile(`[A-Z]`)
		if !passwordRegex.MatchString(data.Password) {
			validationErr.Errors = append(validationErr.Errors, "Deve conter ao menos 1 letra maiúscula")
		}

		passwordRegex = regexp.MustCompile(`(\W|_)`)
		if !passwordRegex.MatchString(data.Password) {
			validationErr.Errors = append(validationErr.Errors, "Deve conter no mínimo 1 caracter especial")
		}

		passwordRegex = regexp.MustCompile(`.{8,}`)
		if !passwordRegex.MatchString(data.Password) {
			validationErr.Errors = append(validationErr.Errors, "Deve conter no mínimo 8 caracteres")
		}
	}
	
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
