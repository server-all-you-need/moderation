package config

import (
	"os"

	"gopkg.in/yaml.v3"
)

func ValidateV2RuntimeConfigFile(path string) error {
	if path == "" {
		return nil
	}
	content, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}
	return ValidateV2RuntimeConfigYAML(content)
}

func ValidateV2RuntimeConfigYAML(content []byte) error {
	var root map[string]any
	if err := yaml.Unmarshal(content, &root); err != nil {
		return err
	}
	section, ok := root["aliyun_audit"].(map[string]any)
	if !ok {
		return nil
	}
	if _, ok := section["text_moderation_service"]; ok {
		return validationError("aliyun_audit.text_moderation_service is not supported; provider service is selected by moderation policy")
	}
	return nil
}
