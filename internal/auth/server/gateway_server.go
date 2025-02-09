package server

import (
	"context"
	pb "github.com/Dmitriy-M1319/crystal-auth/pkg/crystal-auth/v1"
	"github.com/grpc-ecosystem/grpc-gateway/v2/runtime"
	"github.com/rs/cors"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"net/http"
)

func createGatewayServer(grpcAddr, gatewayAddr string) *http.Server {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	mux := runtime.NewServeMux()
	opts := []grpc.DialOption{grpc.WithTransportCredentials(insecure.NewCredentials())}
	err := pb.RegisterAuthServiceHandlerFromEndpoint(ctx, mux, gatewayAddr, opts)
	if err != nil {
		return nil
	}

	c := cors.New(cors.Options{
		AllowedOrigins:   []string{"*"}, // Разрешить все источники
		AllowedMethods:   []string{"GET", "POST", "PUT", "DELETE", "OPTIONS"},
		AllowedHeaders:   []string{"*"},
		AllowCredentials: true,
	})

	handler := c.Handler(mux)

	gatewayServer := &http.Server{
		Addr:    gatewayAddr,
		Handler: handler,
	}

	return gatewayServer
}
