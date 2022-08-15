package redis

import (
	setting "bluebell/settings"
	"fmt"

	"github.com/go-redis/redis"
)

// 声明一个全局的rdb变量
var (
	client *redis.Client
	Nil    = redis.Nil
)

// 初始化连接
func Init(cfg *setting.RedisConfig) (err error) {
	client = redis.NewClient(&redis.Options{
		Addr: fmt.Sprintf("%s:%d",
			//viper.GetString("redis.host"),
			//viper.GetInt("redis.port")),
			cfg.Host,
			cfg.Port),
		//Password: viper.GetString("redis.password"), // no password set
		//DB:       viper.GetInt("redis.db"),          // use default DB
		//PoolSize: viper.GetInt("redis.pool_size"),
		Password: cfg.Password, // no password set
		DB:       cfg.DB,       // use default DB
		PoolSize: cfg.PoolSize,
	})

	return
}

func Close() {
	client.Close()
}
