package main

import (
	"flag"
	"fmt"
	"io"
	"os"

	"github.com/Dmitriy-M1319/crystal-auth/internal/auth/db"
	"github.com/Dmitriy-M1319/crystal-auth/internal/auth/server"
	"github.com/Dmitriy-M1319/crystal-auth/internal/config"
	"github.com/Graylog2/go-gelf/gelf"
	"github.com/pressly/goose"
	"github.com/redis/go-redis/v9"
	"github.com/rs/zerolog/log"
)

func main() {
	if err := config.ReadConfigYML("config.yaml"); err != nil {
		log.Fatal().Err(err).Msg("Failed init configuration")
	}

	cfg := config.GetConfigInstance()

	gelfWriter, err := gelf.NewWriter(cfg.Logging.Address)
	if err != nil {
		log.Fatal().Err(err).Msg("gelf.NewWriter %s")
	}
	log.Output(io.MultiWriter(os.Stderr, gelfWriter))

	migration := flag.Bool("migration", true, "Defines the migration start option")
	flag.Parse()

	conn, err := db.NewConnection(cfg.Database.Host, cfg.Database.User, cfg.Database.Password, cfg.Database.Name)
	if err != nil {
		log.Fatal().Err(err).Msg("Failed init postgres")
	}
	defer db.Close(conn)

	if *migration {
		err = goose.Up(conn.DB, cfg.Database.Migrations)
		if err != nil {
			log.Fatal().Err(err).Msg("Failed to up migrations")
		}
	}

	client := redis.NewClient(&redis.Options{
		Addr:     fmt.Sprintf("%s:%d", cfg.Redis.Host, cfg.Redis.Port),
		Password: cfg.Redis.Password,
		DB:       int(cfg.Redis.Database),
	})

	if err := server.NewGrpcServer(conn, client).Start(&cfg); err != nil {
		log.Error().Err(err).Msg("Failed creating gRPC server")
		return
	}

}
