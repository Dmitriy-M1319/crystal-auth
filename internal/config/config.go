package config

import (
	"gopkg.in/yaml.v3"
	"os"
)

var cfg *Config

func GetConfigInstance() Config {
	if cfg != nil {
		return *cfg
	}

	return Config{}
}

// Database - contains all parameters database connection.
type Database struct {
	Host       string `yaml:"host"`
	Port       string `yaml:"port"`
	User       string `yaml:"user"`
	Password   string `yaml:"password"`
	Migrations string `yaml:"migrations"`
	Name       string `yaml:"name"`
}

type Grpc struct {
	Host              string `yaml:"host"`
	Port              string `yaml:"port"`
	GatewayHost       string `yaml:"gatewayHost"`
	GatewayPort       string `yaml:"gatewayPort"`
	MaxConnectionIdle int64  `yaml:"maxConnectionIdle"`
	Timeout           int64  `yaml:"timeout"`
	MaxConnectionAge  int64  `yaml:"maxConnectionAge"`
}

type Status struct {
	Port          int    `yaml:"port"`
	Host          string `yaml:"host"`
	VersionPath   string `yaml:"versionPath"`
	LivenessPath  string `yaml:"livenessPath"`
	ReadinessPath string `yaml:"readinessPath"`
}

// Config - contains all configuration parameters in config package.
type Config struct {
	Database Database `yaml:"database"`
	Grpc     Grpc     `yaml:"grpc"`
	Status   Status   `yaml:"status"`
}

// ReadConfigYML - read configurations from file and init instance Config.
func ReadConfigYML(configYML string) error {
	if cfg != nil {
		return nil
	}

	file, err := os.Open(configYML)
	if err != nil {
		return err
	}
	defer file.Close()

	decoder := yaml.NewDecoder(file)
	if err := decoder.Decode(&cfg); err != nil {
		return err
	}

	return nil
}
