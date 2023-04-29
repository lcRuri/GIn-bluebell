package tailfile

import (
	"bluebell/dao/kafka"
	"context"
	"github.com/Shopify/sarama"
	"github.com/hpcloud/tail"
	"github.com/sirupsen/logrus"
	"strings"
	"time"
)

type tailTask struct {
	path   string
	topic  string
	tObj   *tail.Tail
	ctx    context.Context
	cancel context.CancelFunc
}

func newTailTask(path, topic string) *tailTask {
	ctx, cancelFunc := context.WithCancel(context.Background())
	tt := &tailTask{
		path:   path,
		topic:  topic,
		ctx:    ctx,
		cancel: cancelFunc,
	}

	return tt
}

func (t *tailTask) Init() (err error) {
	cfg := tail.Config{
		ReOpen:    true,
		Follow:    true,
		Location:  &tail.SeekInfo{Offset: 0, Whence: 2},
		MustExist: false,
		Poll:      true,
	}

	t.tObj, err = tail.TailFile(t.path, cfg)
	return
}

// 读取日志
func (t *tailTask) run() {
	//读取日志发送给kafka
	// TailObj->log->Client->kafka

	logrus.Infof("collect for path:%s is running...", t.path)
	for {
		select {
		case <-t.ctx.Done(): //调用cancel取消
			logrus.Infof("path:%s cancel", t.path)
			return
		case line, ok := <-t.tObj.Lines:
			if !ok {
				logrus.Warn("tail file close reopen,filename:%s\n", t.path)
				time.Sleep(1 * time.Second)
				continue
			}
			//避免空行
			if len(strings.Trim(line.Text, "\r")) == 0 {
				logrus.Info("出现空行，跳过...")
				continue
			}
			//利用通道将同步的代码改为异步的
			//把读出来的一行日志包装成kafka里面的msg类型，丢到通道中
			msg := &sarama.ProducerMessage{}
			msg.Topic = t.topic
			msg.Value = sarama.StringEncoder(line.Text)

			//丢到管道中
			kafka.ToMsgChan(msg)

		}

	}
}
