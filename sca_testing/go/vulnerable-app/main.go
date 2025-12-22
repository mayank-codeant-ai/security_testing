package main

import (
	"fmt"
	"log"
	"net/http"

	// Vulnerable dependencies
	jwt "github.com/dgrijalva/jwt-go"
	"github.com/gin-gonic/gin"
	"github.com/gorilla/websocket"
	"github.com/russross/blackfriday"
	"github.com/tidwall/gjson"
	"gopkg.in/yaml.v2"

	// Healthy dependencies
	"github.com/google/uuid"
	"github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
	"go.uber.org/zap"
)

// Config structure using vulnerable YAML parser
type Config struct {
	Server   ServerConfig   `yaml:"server"`
	Database DatabaseConfig `yaml:"database"`
}

type ServerConfig struct {
	Port string `yaml:"port"`
	Host string `yaml:"host"`
}

type DatabaseConfig struct {
	URL      string `yaml:"url"`
	Username string `yaml:"username"`
	Password string `yaml:"password"`
}

var upgrader = websocket.Upgrader{
	CheckOrigin: func(r *http.Request) bool {
		return true // Vulnerable: allows all origins
	},
}

// Vulnerable JWT handling using dgrijalva/jwt-go
func generateToken(username string) (string, error) {
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"username": username,
		"admin":    false,
	})

	// Vulnerable: weak secret key
	tokenString, err := token.SignedString([]byte("secret"))
	return tokenString, err
}

// Vulnerable markdown rendering using blackfriday
func renderMarkdown(input string) string {
	output := blackfriday.MarkdownCommon([]byte(input))
	return string(output)
}

// Vulnerable JSON parsing using gjson
func parseJSON(jsonStr string) string {
	value := gjson.Get(jsonStr, "data.user.name")
	return value.String()
}

// Vulnerable YAML parsing
func loadConfig(yamlData []byte) (*Config, error) {
	var config Config
	err := yaml.Unmarshal(yamlData, &config)
	return &config, err
}

// Healthy logging setup using zap
func setupLogger() *zap.Logger {
	logger, _ := zap.NewProduction()
	return logger
}

// Healthy UUID generation
func generateUUID() string {
	return uuid.New().String()
}

// Healthy logging with logrus
func logWithLogrus() {
	logrus.SetLevel(logrus.InfoLevel)
	logrus.Info("Application started")
}

// Vulnerable websocket handler
func handleWebSocket(w http.ResponseWriter, r *http.Request) {
	conn, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		log.Println(err)
		return
	}
	defer conn.Close()

	for {
		messageType, p, err := conn.ReadMessage()
		if err != nil {
			log.Println(err)
			return
		}
		// Echo message back (vulnerable to injection)
		if err := conn.WriteMessage(messageType, p); err != nil {
			log.Println(err)
			return
		}
	}
}

// Vulnerable Gin router setup
func setupRouter() *gin.Engine {
	router := gin.Default()

	router.GET("/", func(c *gin.Context) {
		c.JSON(200, gin.H{
			"message": "Vulnerable Application",
		})
	})

	router.POST("/login", func(c *gin.Context) {
		username := c.PostForm("username")
		token, _ := generateToken(username)
		c.JSON(200, gin.H{
			"token": token,
		})
	})

	router.GET("/markdown", func(c *gin.Context) {
		input := c.Query("input")
		output := renderMarkdown(input)
		c.String(200, output)
	})

	router.GET("/ws", func(c *gin.Context) {
		handleWebSocket(c.Writer, c.Request)
	})

	return router
}

// Healthy CLI setup using cobra and viper
func setupCLI() *cobra.Command {
	rootCmd := &cobra.Command{
		Use:   "vulnerable-app",
		Short: "A vulnerable application for testing SCA",
		Run: func(cmd *cobra.Command, args []string) {
			fmt.Println("Running vulnerable app...")
		},
	}

	rootCmd.PersistentFlags().String("config", "", "config file")
	viper.BindPFlag("config", rootCmd.PersistentFlags().Lookup("config"))

	return rootCmd
}

func main() {
	// Initialize healthy components
	logger := setupLogger()
	defer logger.Sync()

	logWithLogrus()
	fmt.Println("UUID:", generateUUID())

	// Setup CLI
	cmd := setupCLI()
	if err := cmd.Execute(); err != nil {
		logger.Fatal("Failed to execute command", zap.Error(err))
	}

	// Setup vulnerable router
	router := setupRouter()
	router.Run(":8080")
}
