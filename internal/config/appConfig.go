package config

import "github.com/Xushengqwer/go-common/config"

// AppConfig 是整个应用的配置结构体
type AppConfig struct {
	ZapConfig     config.ZapConfig    `mapstructure:"zapConfig" json:"zapConfig" config.development.yaml:"zapConfig"`
	TracerConfig  config.TracerConfig `mapstructure:"tracerConfig" json:"tracerConfig" yaml:"tracerConfig"`
	Kafka         KafkaConfig         `mapstructure:"kafka"`
	AuditPlatform string              `mapstructure:"audit_platform"` //  选择审核的云平台
	AliyunAudit   AliyunConfig        `mapstructure:"aliyun_audit"`
	AdminAudit    AdminAuditConfig    `mapstructure:"admin_audit"`
	Log           config.ZapConfig    `mapstructure:"log"`
}

type AdminAuditConfig struct {
	DatabaseURL            string `mapstructure:"database_url"`
	PlatformEnvironmentKey string `mapstructure:"platform_environment_key"`
}
