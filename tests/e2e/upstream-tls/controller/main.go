package main

import (
	"context"
	"crypto/tls"
	"fmt"
	"log"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"connectrpc.com/connect"

	pb "github.com/InteractionLabs/traversal-connector/connector-lib/gen/connector/v1"
	"github.com/InteractionLabs/traversal-connector/connector-lib/gen/connector/v1/connectorconnect"
)

type controller struct {
	mu       sync.Mutex
	complete bool
}

func (c *controller) Tunnel(
	ctx context.Context,
	stream *connect.BidiStream[pb.ConnectorMessage, pb.ControllerMessage],
) error {
	caseToken := os.Getenv("CASE_TOKEN")
	requestID := "upstream-tls-e2e-" + caseToken
	if _, err := stream.Receive(); err != nil {
		return err
	}

	c.mu.Lock()
	if c.complete {
		c.mu.Unlock()
		<-ctx.Done()
		return ctx.Err()
	}
	c.mu.Unlock()

	if err := stream.Send(&pb.ControllerMessage{
		RequestId: requestID,
		Message: &pb.ControllerMessage_HttpRequest{HttpRequest: &pb.HttpRequest{
			Method: http.MethodGet,
			Url:    "https://upstream-tls:8443/probe",
		}},
	}); err != nil {
		return err
	}

	for {
		message, err := stream.Receive()
		if err != nil {
			return err
		}
		if message.GetRequestId() != requestID {
			continue
		}

		if err := validateResult(message); err != nil {
			log.Printf("CASE_FAIL: %s: %v", caseToken, err)
			return connect.NewError(connect.CodeInternal, err)
		}
		c.mu.Lock()
		c.complete = true
		c.mu.Unlock()
		log.Printf("CASE_PASS: %s: %s", caseToken, os.Getenv("EXPECT"))
		return nil
	}
}

func validateResult(message *pb.ConnectorMessage) error {
	switch os.Getenv("EXPECT") {
	case "success":
		response := message.GetHttpResponse()
		if response == nil {
			return fmt.Errorf("wanted HTTP response, got %T", message.GetMessage())
		}
		if response.GetHttpStatus() != http.StatusOK || string(response.GetBody()) != "shim-ok\n" {
			return fmt.Errorf(
				"unexpected upstream response: status=%d body=%q",
				response.GetHttpStatus(), response.GetBody(),
			)
		}
		return nil
	case "unknown-authority":
		response := message.GetErrorResponse()
		if response == nil {
			return fmt.Errorf("wanted error response, got %T", message.GetMessage())
		}
		if !strings.Contains(strings.ToLower(response.GetMessage()), "unknown authority") {
			return fmt.Errorf("error did not contain unknown authority: %q", response.GetMessage())
		}
		return nil
	default:
		return fmt.Errorf("unsupported EXPECT value %q", os.Getenv("EXPECT"))
	}
}

func main() {
	cert, err := tls.LoadX509KeyPair("/certs/tls.crt", "/certs/tls.key")
	if err != nil {
		log.Fatalf("load shim certificate: %v", err)
	}

	shim := &http.Server{
		Addr:              ":8443",
		ReadHeaderTimeout: 5 * time.Second,
		TLSConfig: &tls.Config{
			Certificates: []tls.Certificate{cert},
			MinVersion:   tls.VersionTLS12,
		},
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path != "/probe" {
				http.NotFound(w, r)
				return
			}
			_, _ = w.Write([]byte("shim-ok\n"))
		}),
	}
	go func() {
		if err := shim.ListenAndServeTLS("", ""); err != nil && err != http.ErrServerClosed {
			log.Fatalf("serve HTTPS shim: %v", err)
		}
	}()

	path, handler := connectorconnect.NewConnectorServiceHandler(&controller{})
	mux := http.NewServeMux()
	mux.Handle(path, handler)
	server := &http.Server{
		Addr:              ":9080",
		Handler:           mux,
		ReadHeaderTimeout: 5 * time.Second,
		Protocols:         new(http.Protocols),
	}
	server.Protocols.SetUnencryptedHTTP2(true)
	log.Printf(
		"controller and HTTPS shim listening; case=%s expectation=%s",
		os.Getenv("CASE_TOKEN"), os.Getenv("EXPECT"),
	)
	log.Fatal(server.ListenAndServe())
}
