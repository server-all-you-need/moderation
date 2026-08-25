package config

// AliyunConfig 包含了阿里云内容安全审核服务的配置
type AliyunConfig struct {
	AccessKeyID     string   `mapstructure:"access_key_id"`
	AccessKeySecret string   `mapstructure:"access_key_secret"`
	RegionID        string   `mapstructure:"region_id"` // 例如 "cn-shanghai"
	Endpoint        string   `mapstructure:"endpoint"`  // 例如 "green-cip.cn-shanghai.aliyuncs.com"
	TimeoutMs       int64    `mapstructure:"timeout_ms"`
	Scenes          []string `mapstructure:"scenes"`
}

func (cfg AliyunConfig) EndpointOrDefault() string {
	if cfg.Endpoint != "" {
		return cfg.Endpoint
	}
	return "green-cip.cn-shanghai.aliyuncs.com"
}

func (cfg AliyunConfig) RegionOrDefault() string {
	if cfg.RegionID != "" {
		return cfg.RegionID
	}
	return "cn-shanghai"
}
