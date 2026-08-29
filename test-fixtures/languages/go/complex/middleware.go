package main

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"time"
)

type Middleware func(http.Handler) http.Handler

func AuthMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		token := r.Header.Get("Authorization")
		if token == "" {
			http.Error(w, "Unauthorized", 401)
			return
		}
		if !strings.HasPrefix(token, "Bearer ") {
			http.Error(w, "Invalid token format", 401)
			return
		}
		tokenValue := strings.TrimPrefix(token, "Bearer ")
		if !validateToken(tokenValue) {
			http.Error(w, "Invalid token", 401)
			return
		}
		next.ServeHTTP(w, r)
	})
}

func RateLimiter(maxRequests int, windowMs int64) Middleware {
	type clientInfo struct {
		timestamps []int64
		mu         sync.Mutex
	}
	clients := make(map[string]*clientInfo)
	var mu sync.Mutex

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			clientIP := r.RemoteAddr
			mu.Lock()
			if _, exists := clients[clientIP]; !exists {
				clients[clientIP] = &clientInfo{}
			}
			client := clients[clientIP]
			mu.Unlock()

			client.mu.Lock()
			now := time.Now().UnixMilli()
			windowStart := now - windowMs
			var valid []int64
			for _, ts := range client.timestamps {
				if ts > windowStart {
					valid = append(valid, ts)
				}
			}
			valid = append(valid, now)
			client.timestamps = valid
			count := len(valid)
			client.mu.Unlock()

			if count > maxRequests {
				http.Error(w, "Too many requests", 429)
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}

func CORSMiddleware(allowedOrigins []string) Middleware {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			origin := r.Header.Get("Origin")
			for _, allowed := range allowedOrigins {
				if allowed == "*" || allowed == origin {
					w.Header().Set("Access-Control-Allow-Origin", origin)
					break
				}
			}
			w.Header().Set("Access-Control-Allow-Methods", "GET,POST,PUT,DELETE")
			w.Header().Set("Access-Control-Allow-Headers", "Content-Type,Authorization")
			if r.Method == "OPTIONS" {
				w.WriteHeader(204)
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}

func LoggingMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		next.ServeHTTP(w, r)
		duration := time.Since(start)
		// VULN: Log injection
		userAgent := r.Header.Get("User-Agent")
		fmt.Printf("REQUEST: %s %s %s %v\n", r.Method, r.URL.Path, userAgent, duration)
	})
}

func RecoveryMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer func() {
			if err := recover(); err != nil {
				fmt.Printf("PANIC: %v\n", err)
				http.Error(w, "Internal Server Error", 500)
			}
		}()
		next.ServeHTTP(w, r)
	})
}

func validateToken(token string) bool {
	secret := "gateway-secret-key"
	parts := strings.SplitN(token, ".", 2)
	if len(parts) != 2 {
		return false
	}
	payload := parts[0]
	signature := parts[1]
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(payload))
	expected := hex.EncodeToString(mac.Sum(nil))
	return hmac.Equal([]byte(signature), []byte(expected))
}

func generateToken(payload string) string {
	secret := "gateway-secret-key"
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(payload))
	signature := hex.EncodeToString(mac.Sum(nil))
	return payload + "." + signature
}

func main() {
	fmt.Println("Cloud API Gateway starting...")
}
