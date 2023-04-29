package tailfile

import (
	setting "bluebell/settings"
	"github.com/sirupsen/logrus"
)

type tailTaskMgr struct {
	tailTaskMap map[string]*tailTask
	//所有配置项
	collectEntryList []setting.CollectEntry
	//等待新配置的通道
	confChan chan []setting.CollectEntry
}

var (
	ttMgr *tailTaskMgr
)

func Init(allConf []setting.CollectEntry) (err error) {
	ttMgr = &tailTaskMgr{
		tailTaskMap:      make(map[string]*tailTask, 20),
		collectEntryList: allConf,
		confChan:         make(chan []setting.CollectEntry),
	}

	//allConf存了若干个日志的收集项
	//针对每个日志收集项创建一个对应的tailObj
	for _, conf := range allConf {
		tt := newTailTask(conf.Path, conf.Topic)
		err := tt.Init()
		if err != nil {
			logrus.Errorf("create tailObj for path:%s failed,err:%v", conf.Path, err)
			continue
		}

		//去收集日志
		logrus.Infof("create a tail task for path:%s success", conf.Path)
		//把创建的tailtask存储到ttMgr
		ttMgr.tailTaskMap[tt.path] = tt

		go tt.run()
	}

	//在后台监听新的配置
	go ttMgr.watch()

	return
}

// 监听etcd里面配置是否更新
func (t *tailTaskMgr) watch() {
	for {
		//接受新配置
		newConf := <-t.confChan
		logrus.Infof("get new conf from etcd,conf:%v,start managing tailtask", newConf)
		for _, conf := range newConf {
			//判断新的配置里面的任务之前是否存在
			//如果存在 不要动 不存在 添加 如果之前有但是现在没有 停掉
			//之前存在
			if t.isExist(conf) {
				continue
			}
			//之前不存在
			tt := newTailTask(conf.Path, conf.Topic)
			err := tt.Init()
			if err != nil {
				logrus.Errorf("create tailObj for path:%s failed,err:%v", conf.Path, err)
				return
			}
			logrus.Infof("create a tail task for path:%s success", conf.Path)
			t.tailTaskMap[conf.Path] = tt
			//后台去收集日志
			go tt.run()
		}

		//找到在tailTaskMap里面存在，但是newconf里面不存在的tailtask
		for key, task := range t.tailTaskMap {
			var found bool
			for _, conf := range newConf {
				if key == conf.Path {
					found = true
					break
				}
			}
			//当前key在现在新的conf里面不存在，需要停掉之前的goroutine
			if !found {
				//使用task里面的ctx的cancel取消掉goroutine
				logrus.Infof("the task collect path:%s is stopping", key)
				delete(t.tailTaskMap, key)
				task.cancel()
			}
		}
	}

}

func (t *tailTaskMgr) isExist(conf setting.CollectEntry) bool {
	_, ok := t.tailTaskMap[conf.Path]
	return ok
}

func SendNewConf(newConf []setting.CollectEntry) {
	ttMgr.confChan <- newConf
}
