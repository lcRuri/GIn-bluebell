package setting

// 要收集的日志的配置项1
type CollectEntry struct {
	Path  string `json:"path"`
	Topic string `json:"topic"`
}
