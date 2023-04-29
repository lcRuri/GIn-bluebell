package etcd

import (
	"bluebell/dao/tailfile"
	setting "bluebell/settings"
	"context"
	"encoding/json"
	"fmt"
	"github.com/coreos/etcd/clientv3"
	"github.com/sirupsen/logrus"
	"time"
)

var (
	client *clientv3.Client
)

func Init(cfg *setting.EtcdConfig) (err error) {
	address := []string{cfg.Address}
	client, err = clientv3.New(clientv3.Config{
		Endpoints:   address,
		DialTimeout: time.Second * 5,
	})
	if err != nil {
		fmt.Printf("connect to etcd failed,err:%v\n", err)
		return
	}

	return
}

// 拉取日志收集的函数
func GetConf(key string) (collectEntryList []setting.CollectEntry, err error) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second*5)
	defer cancel()
	//从etcd中读取key对应的json值
	resp, err := client.Get(ctx, key)
	if err != nil {
		logrus.Errorf("get conf from etcd by key:%s failed,err:%v", key, err)
		return
	}

	if len(resp.Kvs) == 0 {
		logrus.Warningf("get len:0 from etcd by key:%s failed,err:%v", key, err)
		return
	}

	ret := resp.Kvs[0]
	//json格式字符串
	fmt.Println(ret.Value)
	err = json.Unmarshal(ret.Value, &collectEntryList)
	if err != nil {
		logrus.Errorf("json unmarshal failed,err:%v", err)
		return
	}

	return
}

// 监控etcd里面的日志收集项目里面的变化
func WatchConf(key string) {
	for {
		watchCh := client.Watch(context.Background(), key)
		for wresp := range watchCh {
			logrus.Info("get new conf from etcd!")
			for _, evt := range wresp.Events {
				fmt.Printf("etcd changed:type:%s key:%s value:%s\n", evt.Type, evt.Kv.Key, evt.Kv.Value)
				var newConf []setting.CollectEntry
				//如果etcd进行删除操作
				if evt.Type == clientv3.EventTypeDelete {
					//给chan传入一个空值
					logrus.Warning("etcd delete the key!")
					tailfile.SendNewConf(newConf)
					continue
				}

				err := json.Unmarshal(evt.Kv.Value, &newConf)
				if err != nil {
					logrus.Errorf("json unmarshal new conf failed,err:%v", err)
					continue
				}

				//告诉tailfile启用新的配置
				tailfile.SendNewConf(newConf) //没有人接收就是阻塞的
			}
		}
	}

}
