FROM golang:1.23-alpine

RUN apt-get update && apt-get install protobuf-compiler

RUN go install github.com/grpc-ecosystem/grpc-gateway/v2/protoc-gen-grpc-gateway@latest \
    && go install github.com/grpc-ecosystem/grpc-gateway/v2/protoc-gen-openapiv2@latest \
    && go install google.golang.org/grpc/cmd/protoc-gen-go-grpc\
	&& go install google.golang.org/protobuf/cmd/protoc-gen-go

WORKDIR /code
COPY go.mod .
RUN go mod download
COPY . .

EXPOSE 8083
EXPOSE 8000
EXPOSE 12201

CMD ["go run cmd/crystal-auth/main.go"]

