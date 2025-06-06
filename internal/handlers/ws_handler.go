package handlers

import (
	"encoding/json"
	"log"
	"net/http"
	"sync"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/gorilla/websocket"
)

// Hub хранит подключения клиентов, сгруппированные по queueID.
type Hub struct {
	// Для каждой очереди (queueID) храним множество подключений.
	clients map[string]map[*Client]bool
	// Канал для регистрации нового клиента.
	register chan *Client
	// Канал для удаления клиента.
	unregister chan *Client
	// Канал для трансляции сообщений по конкретной очереди.
	broadcast chan BroadcastMessage
	// Mutex для защиты карты клиентов.
	mu sync.RWMutex
}

// BroadcastMessage представляет сообщение для рассылки в определённую очередь.
type BroadcastMessage struct {
	QueueID string
	Message []byte
}

type WSMessage struct {
	EventType string      `json:"event_type"`     // Тип события: "user_joined", "user_left", "queue_closed", "queue_update", ...
	QueueID   string      `json:"queue_id"`       // Идентификатор очереди (как строка)
	Data      interface{} `json:"data,omitempty"` // Дополнительные данные, зависящие от события
	Timestamp int64       `json:"timestamp"`      // Метка времени (Unix)
}

// Создаем глобальный экземпляр хаба.
var HubInstance = NewHub()

// NewHub создает новый Hub.
func NewHub() *Hub {
	return &Hub{
		clients:    make(map[string]map[*Client]bool),
		register:   make(chan *Client),
		unregister: make(chan *Client),
		broadcast:  make(chan BroadcastMessage),
	}
}

// Run запускает цикл обработки каналов хаба.
func (h *Hub) Run() {
	for {
		select {
		case client := <-h.register:
			h.mu.Lock()
			if h.clients[client.QueueID] == nil {
				h.clients[client.QueueID] = make(map[*Client]bool)
			}
			h.clients[client.QueueID][client] = true
			h.mu.Unlock()
		case client := <-h.unregister:
			h.mu.Lock()
			if clients, ok := h.clients[client.QueueID]; ok {
				if _, ok := clients[client]; ok {
					delete(clients, client)
					close(client.Send)
					if len(clients) == 0 {
						delete(h.clients, client.QueueID)
					}
				}
			}
			h.mu.Unlock()
		case message := <-h.broadcast:
			h.mu.RLock()
			if clients, ok := h.clients[message.QueueID]; ok {
				for client := range clients {
					select {
					case client.Send <- message.Message:
					default:
						close(client.Send)
						delete(clients, client)
					}
				}
			}
			h.mu.RUnlock()
		}
	}
}

// Client представляет одно подключение через WebSocket.
type Client struct {
	Hub     *Hub
	Conn    *websocket.Conn
	Send    chan []byte
	QueueID string
}

// readPump читает сообщения из WebSocket-соединения.
// В данном примере мы не обрабатываем входящие сообщения, а просто отслеживаем разрыв соединения.
func (c *Client) readPump() {
	defer func() {
		c.Hub.unregister <- c
		c.Conn.Close()
	}()
	c.Conn.SetReadLimit(512)
	c.Conn.SetReadDeadline(time.Now().Add(60 * time.Second))
	c.Conn.SetPongHandler(func(string) error {
		c.Conn.SetReadDeadline(time.Now().Add(60 * time.Second))
		return nil
	})
	for {
		_, message, err := c.Conn.ReadMessage()
		if err != nil {
			// Можно добавить логирование ошибок, если нужно.
			break
		}
		// В простейшем случае можно просто логировать входящие сообщения.
		log.Printf("Получено сообщение от клиента: %s", message)
	}
}

// writePump отправляет сообщения клиенту из канала Send.
func (c *Client) writePump() {
	ticker := time.NewTicker(54 * time.Second)
	defer func() {
		ticker.Stop()
		c.Conn.Close()
	}()
	for {
		select {
		case message, ok := <-c.Send:
			c.Conn.SetWriteDeadline(time.Now().Add(10 * time.Second))
			if !ok {
				// Канал закрыт.
				c.Conn.WriteMessage(websocket.CloseMessage, []byte{})
				return
			}
			if err := c.Conn.WriteMessage(websocket.TextMessage, message); err != nil {
				return
			}
		case <-ticker.C:
			// Отправка ping-сообщения для поддержания соединения.
			c.Conn.SetWriteDeadline(time.Now().Add(10 * time.Second))
			if err := c.Conn.WriteMessage(websocket.PingMessage, nil); err != nil {
				return
			}
		}
	}
}

// Настраиваем апгрейдер для WebSocket с разрешением всех источников.
var upgrader = websocket.Upgrader{
	CheckOrigin: func(r *http.Request) bool {
		return true
	},
}

//	QueueWebSocketHandler обновляет соединение до WebSocket и регистрирует клиента в Hub.
//
// @Summary		Подключение к WebSocket очереди
// @Description	Устанавливает WebSocket соединение для получения обновлений очереди в реальном времени
// @Tags			websocket
// @Accept			json
// @Produce		json
// @Param			id	path		string	true	"ID очереди"
// @Security		BearerAuth
// @Success		101	{string}	string	"Переключение протокола на WebSocket"
// @Failure		400	{object}	response.ErrorResponse	"Ошибка валидации (INVALID_QUEUE_ID)"
// @Failure		500	{object}	response.ErrorResponse	"Ошибка сервера (WEBSOCKET_ERROR)"
// @Router			/api/queues/{id}/ws [get]
func QueueWebSocketHandler(c *gin.Context) {
	queueID := c.Param("id")
	conn, err := upgrader.Upgrade(c.Writer, c.Request, nil)
	if err != nil {
		http.Error(c.Writer, "Ошибка обновления до WebSocket", http.StatusInternalServerError)
		return
	}
	// Создаем нового клиента
	client := &Client{
		Hub:     HubInstance,
		Conn:    conn,
		Send:    make(chan []byte, 256),
		QueueID: queueID,
	}
	// Регистрируем клиента в Hub
	HubInstance.register <- client

	// Запускаем горутины для отправки и приема сообщений
	go client.writePump()
	client.readPump()
}

func (h *Hub) BroadcastWSMessage(msg WSMessage) {
	msg.Timestamp = time.Now().Unix()
	b, err := json.Marshal(msg)
	if err != nil {
		// Если не удалось сериализовать, логируем и выходим.
		log.Println("Ошибка сериализации WSMessage:", err)
		return
	}
	h.broadcast <- BroadcastMessage{
		QueueID: msg.QueueID,
		Message: b,
	}
}
