package clients

import (
	"context"
	"encoding/json"
	"fmt"
	"sync"

	amqp "github.com/rabbitmq/amqp091-go"
)

const (
	// QueueName is the name of the notifications queue.
	QueueName = "alkemio-notifications"

	// KratosEventsQueueName is the dedicated durable queue for Kratos-sourced
	// platform events (e.g. USER_PASSWORD_CHANGED). It is intentionally separate
	// from QueueName: the notifications service and the server's @nestjs/microservices
	// consumer must not share a queue or they steal each other's messages.
	KratosEventsQueueName = "alkemio-kratos-events"
)

// RabbitMQClient wraps the RabbitMQ connection for publishing messages.
type RabbitMQClient struct {
	conn    *amqp.Connection
	channel *amqp.Channel
	mu      sync.Mutex
}

// NewRabbitMQClient creates a new RabbitMQ client.
func NewRabbitMQClient(url string) (*RabbitMQClient, error) {
	conn, err := amqp.Dial(url)
	if err != nil {
		return nil, fmt.Errorf("failed to connect to RabbitMQ: %w", err)
	}

	ch, err := conn.Channel()
	if err != nil {
		_ = conn.Close()
		return nil, fmt.Errorf("failed to open channel: %w", err)
	}

	// Declare the durable queues this service publishes to (idempotent).
	for _, queue := range []string{QueueName, KratosEventsQueueName} {
		if _, err = ch.QueueDeclare(
			queue,
			true,  // durable
			false, // delete when unused
			false, // exclusive
			false, // no-wait
			nil,   // arguments
		); err != nil {
			_ = ch.Close()
			_ = conn.Close()
			return nil, fmt.Errorf("failed to declare queue %q: %w", queue, err)
		}
	}

	return &RabbitMQClient{
		conn:    conn,
		channel: ch,
	}, nil
}

// Ping checks connectivity to RabbitMQ.
func (c *RabbitMQClient) Ping() error {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.conn == nil || c.conn.IsClosed() {
		return fmt.Errorf("connection closed")
	}
	if c.channel == nil || c.channel.IsClosed() {
		return fmt.Errorf("channel closed")
	}
	return nil
}

// Close closes the RabbitMQ connection.
func (c *RabbitMQClient) Close() error {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.channel != nil {
		_ = c.channel.Close()
	}
	if c.conn != nil {
		return c.conn.Close()
	}
	return nil
}

// nestEnvelope wraps a message in the NestJS microservices transport format.
// NestJS RMQ transport expects {"pattern": "<event>", "data": <payload>}.
type nestEnvelope struct {
	Pattern string `json:"pattern"`
	Data    any    `json:"data"`
}

// Publish sends a message to the notifications queue wrapped in the NestJS envelope format.
// It delegates to PublishToQueue targeting QueueName for backward compatibility.
func (c *RabbitMQClient) Publish(ctx context.Context, pattern string, event any) error {
	return c.PublishToQueue(ctx, QueueName, pattern, event)
}

// PublishToQueue sends a message to the given durable queue wrapped in the NestJS
// envelope format ({"pattern": <pattern>, "data": <event>}). The message is published
// to the default exchange with the queue name as the routing key.
func (c *RabbitMQClient) PublishToQueue(ctx context.Context, queue, pattern string, event any) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	envelope := nestEnvelope{
		Pattern: pattern,
		Data:    event,
	}

	body, err := json.Marshal(envelope)
	if err != nil {
		return fmt.Errorf("failed to marshal event: %w", err)
	}

	err = c.channel.PublishWithContext(
		ctx,
		"",    // exchange (default)
		queue, // routing key == queue name
		false, // mandatory
		false, // immediate
		amqp.Publishing{
			ContentType: "application/json",
			Body:        body,
		},
	)
	if err != nil {
		return fmt.Errorf("failed to publish message: %w", err)
	}

	return nil
}
