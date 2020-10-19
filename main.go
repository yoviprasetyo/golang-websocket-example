package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"html/template"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"strings"
	"time"

	jwt "github.com/dgrijalva/jwt-go"
	"github.com/gorilla/websocket"
	"github.com/joho/godotenv"
	"github.com/novalagung/gubrak/v2"
)

// H to map.
type H map[string]interface{}

// MessageNewUser variable.
const MessageNewUser = "New User"

// MessageChat variable.
const MessageChat = "Chat"

// MessageLeave variable.
const MessageLeave = "Leave"

var connections = make([]*WebSocketConnection, 0)

var tokenCookieName = "access_token"

// SocketPayload struct.
type SocketPayload struct {
	Message string
}

// SocketResponse struct.
type SocketResponse struct {
	From    string `json:"from"`
	Type    string `json:"type"`
	Message string `json:"message"`
}

// WebSocketConnection struct.
type WebSocketConnection struct {
	*websocket.Conn
	Username string
}

// User struct.
type User struct {
	Username string `json:"username"`
	Password string `json:"password"`
	Token    string `json:"token"`
}

// CustomClaims struct.
type CustomClaims struct {
	jwt.StandardClaims
	Username string
}

func main() {

	godotenv.Load(".env")

	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {

		template, err := template.ParseFiles("index.html")

		if err != nil {
			http.Error(w, "Could not open requested file", http.StatusInternalServerError)
			return
		}

		data := H{
			"title": "Websocket",
		}

		err = template.Execute(w, data)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
		}
	})

	http.HandleFunc("/login", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "POST" {
			responseError(w, http.StatusMethodNotAllowed, "Method not allowed")
			return
		}

		decoder := json.NewDecoder(r.Body)

		user := User{}

		err := decoder.Decode(&user)

		if err != nil {
			responseError(w, http.StatusBadRequest, "Non-well data format")
			return
		}

		if login(user.Username, user.Password) == false {
			w.Header().Set("X-Content-Type-Options", "nosniff")
			responseError(w, http.StatusBadRequest, "User and password not match")
			return
		}

		cookie := &http.Cookie{}

		if storedCookie, _ := r.Cookie(tokenCookieName); storedCookie != nil {
			cookie = storedCookie
		}

		claims := &CustomClaims{
			Username: user.Username,
			StandardClaims: jwt.StandardClaims{
				ExpiresAt: time.Now().Add(60 * time.Minute).Unix(),
				IssuedAt:  time.Now().Unix(),
			},
		}

		sign := jwt.NewWithClaims(jwt.GetSigningMethod("HS256"), claims)

		token, err := sign.SignedString([]byte(os.Getenv("TOKEN_SECRET")))

		if err != nil {
			responseError(w, http.StatusInternalServerError, "Internal server error")
			return
		}

		cookie = &http.Cookie{
			Name:     tokenCookieName,
			Value:    token,
			Expires:  time.Now().Add(60 * time.Minute),
			HttpOnly: true,
			Secure:   true,
			MaxAge:   86400,
		}

		http.SetCookie(w, cookie)

		responseSuccess(w, H{
			"username": user.Username,
		})
	})

	http.HandleFunc("/ws", func(w http.ResponseWriter, r *http.Request) {

		currentGorillaConn, err := websocket.Upgrade(w, r, w.Header(), 1024, 1024)
		if err != nil {
			http.Error(w, "Could not open websocket", http.StatusBadRequest)
		}

		username := r.URL.Query().Get("username")
		currentConn := WebSocketConnection{
			Conn:     currentGorillaConn,
			Username: username,
		}
		connections = append(connections, &currentConn)
		fmt.Println(username, currentConn)
		go handleIO(&currentConn, connections)
	})

	http.ListenAndServe(":8080", nil)
}

func handleIO(currentConn *WebSocketConnection, connections []*WebSocketConnection) {
	defer func() {
		if r := recover(); r != nil {
			log.Println("Error", fmt.Sprintf("%v", r))
		}
	}()

	broadcastMessage(currentConn, MessageNewUser, "")

	for {
		payload := SocketPayload{}
		err := currentConn.ReadJSON(&payload)
		if err != nil {
			if strings.Contains(err.Error(), "websocket: close") {
				broadcastMessage(currentConn, MessageLeave, "")
				ejectConnection(currentConn)
				return
			}

			log.Println("Error", err.Error())
			continue
		}

	}
}

func broadcastMessage(currentConn *WebSocketConnection, kind, message string) {
	for _, eachConn := range connections {
		if eachConn == currentConn {
			continue
		}

		eachConn.WriteJSON(SocketResponse{
			From:    currentConn.Username,
			Type:    kind,
			Message: message,
		})
	}
}

func ejectConnection(currentConn *WebSocketConnection) {
	filtered := gubrak.From(connections).Reject(func(each *WebSocketConnection) bool {
		return each == currentConn
	}).Result()
	connections = filtered.([]*WebSocketConnection)
}

func createTokenCookie(token string) http.Cookie {
	expired := time.Now().Add(60 * time.Minute)
	return http.Cookie{
		Name:     "apaya",
		Value:    token,
		Path:     "/",
		Expires:  expired,
		HttpOnly: true,
		Secure:   true,
		MaxAge:   86400,
	}
}

func login(username, password string) bool {
	users, err := ioutil.ReadFile("users.json")
	if err != nil {
		return false
	}

	data := []User{}

	err = json.Unmarshal(users, &data)
	if err != nil {
		return false
	}

	for _, user := range data {
		if user.Username == username && user.Password == password {
			return true
		}
	}

	return false
}

func validateToken(w http.ResponseWriter, r *http.Request) {
	cookie := &http.Cookie{}
	storedCookie, err := r.Cookie(tokenCookieName)

	if err != nil {

	}

	if storedCookie == nil {

	}

	cookie = storedCookie
	if cookie.Value == "" {

	}

	token, err := jwt.Parse(cookie.Value, func(token *jwt.Token) (interface{}, error) {
		if jwt.GetSigningMethod("HS256") != token.Method {
			return nil, errors.New("Unexpected signing method")
		}

		return []byte(os.Getenv("TOKEN_SECRET")), nil
	})

	if token == nil || err != nil {

	}

}

func responseSuccess(w http.ResponseWriter, h H) {

	json, err := json.Marshal(H{
		"ok":   true,
		"data": h,
	})

	if err != nil {
		responseError(w, http.StatusInternalServerError, "Internal Server Error"+err.Error())
		return
	}

	w.Header().Set("Content-type", "application/json")
	w.Write(json)
}

func responseError(w http.ResponseWriter, statusCode int, errorMessage string) {
	json, err := json.Marshal(H{
		"ok":    false,
		"error": errorMessage,
	})

	if err != nil {
		responseError(w, http.StatusInternalServerError, "Internal Server Error "+err.Error())
		return
	}

	w.Header().Set("Content-type", "application/json")
	w.WriteHeader(statusCode)
	w.Write(json)
}
