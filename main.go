package main

import (
	"fmt"
	"html"
	"log"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/bcrypt"
)

var (
	users   = make(map[string]string)
	usersMu sync.RWMutex
)

const pageStart = `<!DOCTYPE html>
<html lang="ru">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>%s</title>
  <style>
    body {
      font-family: Arial, sans-serif;
      max-width: 650px;
      margin: 50px auto;
      padding: 20px;
      line-height: 1.5;
    }
    form {
      display: flex;
      flex-direction: column;
      gap: 12px;
      max-width: 350px;
    }
    input, button {
      padding: 10px;
      font-size: 16px;
    }
    nav {
      margin-bottom: 25px;
    }
    nav a {
      margin-right: 15px;
    }
    .message {
      padding: 12px;
      background: #eeeeee;
      margin-bottom: 20px;
    }
  </style>
</head>
<body>
  <nav>
    <a href="/">Главная</a>
    <a href="/register">Регистрация</a>
    <a href="/login">Вход</a>
  </nav>`

const pageEnd = `
</body>
</html>`

func main() {
	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/", homeHandler)
	mux.HandleFunc("/register", registerHandler)
	mux.HandleFunc("/login", loginHandler)
	mux.HandleFunc("/health", healthHandler)

	handler := securityHeaders(redirectToHTTPS(mux))

	server := &http.Server{
		Addr:              ":" + port,
		Handler:           handler,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       10 * time.Second,
		WriteTimeout:      10 * time.Second,
		IdleTimeout:       30 * time.Second,
		MaxHeaderBytes:    1 << 20,
	}

	log.Printf("Сервер запущен: http://localhost:%s", port)

	err := server.ListenAndServe()
	if err != nil && err != http.ErrServerClosed {
		log.Fatal(err)
	}
}

func homeHandler(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}

	if r.Method != http.MethodGet {
		w.Header().Set("Allow", http.MethodGet)
		http.Error(w, "Метод не разрешён", http.StatusMethodNotAllowed)
		return
	}

	renderPage(
		w,
		"DevSecOps RGR",
		`<h1>DevSecOps RGR</h1>
    <p>Простое защищённое веб-приложение на языке Go.</p>
    <p>В приложении реализованы регистрация, вход, хэширование паролей,
    защита от кликджекинга и дополнительные HTTP-заголовки безопасности.</p>`,
	)
}

func registerHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodGet {
		renderPage(w, "Регистрация", `
      <h1>Регистрация</h1>
      <form method="post" action="/register">
        <label for="username">Имя пользователя</label>
        <input
          id="username"
          name="username"
          type="text"
          minlength="3"
          maxlength="30"
          required
          autocomplete="username">

        <label for="password">Пароль</label>
        <input
          id="password"
          name="password"
          type="password"
          minlength="8"
          maxlength="72"
          required
          autocomplete="new-password">

        <button type="submit">Зарегистрироваться</button>
      </form>`)
		return
	}

	if r.Method != http.MethodPost {
		w.Header().Set("Allow", "GET, POST")
		http.Error(w, "Метод не разрешён", http.StatusMethodNotAllowed)
		return
	}

	if !parseLimitedForm(w, r) {
		return
	}

	username := strings.TrimSpace(r.Form.Get("username"))
	password := r.Form.Get("password")

	if len(username) < 3 || len(username) > 30 {
		renderMessage(w, "Ошибка", "Имя пользователя должно содержать от 3 до 30 символов.")
		return
	}

	if len(password) < 8 || len(password) > 72 {
		renderMessage(w, "Ошибка", "Пароль должен содержать от 8 до 72 символов.")
		return
	}

	passwordHash, err := hashPassword(password)
	if err != nil {
		http.Error(w, "Не удалось обработать пароль", http.StatusInternalServerError)
		return
	}

	usersMu.Lock()

	if _, exists := users[username]; exists {
		usersMu.Unlock()
		renderMessage(w, "Ошибка", "Пользователь с таким именем уже существует.")
		return
	}

	users[username] = passwordHash
	usersMu.Unlock()

	renderMessage(
		w,
		"Регистрация завершена",
		"Пользователь успешно зарегистрирован. Пароль сохранён в виде bcrypt-хэша.",
	)
}

func loginHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodGet {
		renderPage(w, "Вход", `
      <h1>Вход</h1>
      <form method="post" action="/login">
        <label for="username">Имя пользователя</label>
        <input
          id="username"
          name="username"
          type="text"
          required
          autocomplete="username">

        <label for="password">Пароль</label>
        <input
          id="password"
          name="password"
          type="password"
          required
          autocomplete="current-password">

        <button type="submit">Войти</button>
      </form>`)
		return
	}

	if r.Method != http.MethodPost {
		w.Header().Set("Allow", "GET, POST")
		http.Error(w, "Метод не разрешён", http.StatusMethodNotAllowed)
		return
	}

	if !parseLimitedForm(w, r) {
		return
	}

	username := strings.TrimSpace(r.Form.Get("username"))
	password := r.Form.Get("password")

	usersMu.RLock()
	passwordHash, exists := users[username]
	usersMu.RUnlock()

	if !exists || !checkPasswordHash(password, passwordHash) {
		renderMessage(w, "Ошибка", "Неверное имя пользователя или пароль.")
		return
	}

	renderMessage(w, "Вход выполнен", "Пароль успешно проверен. Вход разрешён.")
}

func healthHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.Header().Set("Allow", http.MethodGet)
		http.Error(w, "Метод не разрешён", http.StatusMethodNotAllowed)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	fmt.Fprint(w, `{"status":"ok"}`)
}

func hashPassword(password string) (string, error) {
	hash, err := bcrypt.GenerateFromPassword(
		[]byte(password),
		bcrypt.DefaultCost,
	)
	if err != nil {
		return "", err
	}

	return string(hash), nil
}

func checkPasswordHash(password, hash string) bool {
	err := bcrypt.CompareHashAndPassword(
		[]byte(hash),
		[]byte(password),
	)

	return err == nil
}

func parseLimitedForm(w http.ResponseWriter, r *http.Request) bool {
	r.Body = http.MaxBytesReader(w, r.Body, 4096)

	if err := r.ParseForm(); err != nil {
		http.Error(
			w,
			"Запрос слишком большой или содержит неверные данные",
			http.StatusBadRequest,
		)
		return false
	}

	return true
}

func securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("Referrer-Policy", "no-referrer")
		w.Header().Set(
			"Permissions-Policy",
			"camera=(), microphone=(), geolocation=()",
		)
		w.Header().Set(
			"Content-Security-Policy",
			"default-src 'self'; "+
				"style-src 'self' 'unsafe-inline'; "+
				"form-action 'self'; "+
				"frame-ancestors 'none'; "+
				"base-uri 'self'",
		)

		if r.TLS != nil ||
			strings.EqualFold(r.Header.Get("X-Forwarded-Proto"), "https") {
			w.Header().Set(
				"Strict-Transport-Security",
				"max-age=31536000; includeSubDomains",
			)
		}

		next.ServeHTTP(w, r)
	})
}

func redirectToHTTPS(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.EqualFold(r.Header.Get("X-Forwarded-Proto"), "http") {
			target := "https://" + r.Host + r.URL.RequestURI()

			http.Redirect(
				w,
				r,
				target,
				http.StatusPermanentRedirect,
			)
			return
		}

		next.ServeHTTP(w, r)
	})
}

func renderMessage(w http.ResponseWriter, title, message string) {
	content := fmt.Sprintf(
		`<h1>%s</h1><div class="message">%s</div>`,
		html.EscapeString(title),
		html.EscapeString(message),
	)

	renderPage(w, title, content)
}

func renderPage(w http.ResponseWriter, title, content string) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")

	fmt.Fprintf(
		w,
		pageStart+"%s"+pageEnd,
		html.EscapeString(title),
		content,
	)
}
