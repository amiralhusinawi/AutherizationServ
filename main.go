
package main

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	"github.com/google/uuid"
	"github.com/joho/godotenv"
	"github.com/go-redis/redis/v8"
	"golang.org/x/crypto/bcrypt"
	"github.com/golang-jwt/jwt/v4"
	"context"
	_ "github.com/lib/pq"
)

var db *sql.DB
var rdb *redis.Client
var jwtKey = []byte("my_secret_key")
var ctx = context.Background()

func main() {
	_ = godotenv.Load()
	initPostgres()
	initRedis()

	r := chi.NewRouter()
	r.Use(middleware.Logger)

	r.Post("/signup", SignupHandler)
	r.Post("/login", LoginHandler)

	r.Group(func(r chi.Router) {
		r.Use(SessionMiddleware)
		r.Get("/protected", ProtectedHandler)
	})

	fmt.Println("[Auth Service] Running on :8080")
	http.ListenAndServe(":8080", r)
}

func initPostgres() {
	pgURL := os.Getenv("POSTGRES_URL")
	var err error
	db, err = sql.Open("postgres", pgURL)
	if err != nil {
		log.Fatal("DB Error:", err)
	}
	if err = db.Ping(); err != nil {
		log.Fatal("Ping Error:", err)
	}
}

func initRedis() {
	rdb = redis.NewClient(&redis.Options{
		Addr:     os.Getenv("REDIS_ADDR"),
		Password: "",
		DB:       0,
	})
	if _, err := rdb.Ping(ctx).Result(); err != nil {
		log.Fatal("Redis Error:", err)
	}
}

type User struct {
	ID           string `json:"id"`
	Email        string `json:"email"`
	PasswordHash string
	Role         string `json:"role"`
}

func SignupHandler(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Name     string `json:"name"`
		Email    string `json:"email"`
		Phone    string `json:"phone"`
		Password string `json:"password"`
		Role     string `json:"role"`
	}
	json.NewDecoder(r.Body).Decode(&req)
	if req.Role == "" || !strings.Contains(req.Email, "@") || len(req.Password) < 6 {
		http.Error(w, "Invalid input", 400)
		return
	}
	uid := fmt.Sprintf("%s_%s", req.Role[:4], uuid.New().String())
	hash, _ := bcrypt.GenerateFromPassword([]byte(req.Password), 12)
	_, err := db.Exec("INSERT INTO users (id, email, password_hash, created_at) VALUES ($1, $2, $3, $4)",
		uid, req.Email, hash, time.Now())
	if err != nil {
		http.Error(w, "DB insert error", 500)
		return
	}
	w.WriteHeader(201)
	json.NewEncoder(w).Encode(map[string]string{"id": uid})
}

func LoginHandler(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Email    string `json:"email"`
		Password string `json:"password"`
	}
	json.NewDecoder(r.Body).Decode(&req)
	row := db.QueryRow("SELECT id, password_hash FROM users WHERE email = $1", req.Email)
	var uid, hash string
	if err := row.Scan(&uid, &hash); err != nil {
		http.Error(w, "Unauthorized", 401)
		return
	}
	if err := bcrypt.CompareHashAndPassword([]byte(hash), []byte(req.Password)); err != nil {
		http.Error(w, "Unauthorized", 401)
		return
	}
	sessionID := uuid.New().String()
	rdb.Set(ctx, sessionID, uid, 7*24*time.Hour)
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"sub":  uid,
		"exp":  time.Now().Add(7 * 24 * time.Hour).Unix(),
		"role": strings.Split(uid, "_")[0],
	})
	jwtStr, _ := token.SignedString(jwtKey)
	json.NewEncoder(w).Encode(map[string]string{
		"token":       jwtStr,
		"session_id":  sessionID,
		"user_id":     uid,
	})
}

func SessionMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		sess := r.Header.Get("X-Session-Token")
		if sess == "" {
			http.Error(w, "Missing session", 401)
			return
		}
		val, err := rdb.Get(ctx, sess).Result()
		if err != nil {
			http.Error(w, "Invalid session", 401)
			return
		}
		rdb.Expire(ctx, sess, 7*24*time.Hour)
		r = r.WithContext(context.WithValue(r.Context(), "user_id", val))
		next.ServeHTTP(w, r)
	})
}

func ProtectedHandler(w http.ResponseWriter, r *http.Request) {
	uid := r.Context().Value("user_id").(string)
	w.Write([]byte("Hello, user " + uid))
}
