FROM golang:1.23

RUN apt-get -y update && apt-get install -y protobuf-compiler

WORKDIR /code
COPY go.mod go.sum ./
RUN go mod download

RUN go install github.com/grpc-ecosystem/grpc-gateway/v2/protoc-gen-grpc-gateway@latest
RUN go install github.com/grpc-ecosystem/grpc-gateway/v2/protoc-gen-openapiv2@latest
RUN go install google.golang.org/grpc/cmd/protoc-gen-go-grpc
RUN go install google.golang.org/protobuf/cmd/protoc-gen-go

COPY . .

EXPOSE 8083
EXPOSE 8000
EXPOSE 12202

CMD ["go", "run", "cmd/crystal-auth/main.go"]
