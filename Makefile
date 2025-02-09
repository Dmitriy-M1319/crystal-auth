.PHONY: auth_proto proto_clean auth_run

auth_proto:
	protoc --experimental_allow_proto3_optional \
		-I protos \
		--go_out=pkg --go_opt=paths=source_relative \
		--go-grpc_out=pkg --go-grpc_opt=paths=source_relative \
		--grpc-gateway_out=pkg --grpc-gateway_opt=generate_unbound_methods=true --grpc-gateway_opt=paths=source_relative \
		--openapiv2_out=swagger \
		protos/crystal-auth/v1/auth.proto
proto_clean:
	rm -rf pkg/crystal-auth
auth_run:
	go run cmd/crystal-auth/main.go
