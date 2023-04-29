package kafka

import (
	setting "bluebell/settings"
	"fmt"
	"github.com/Shopify/sarama"
)

var (
	client  sarama.SyncProducer
	msgChan chan *sarama.ProducerMessage
)

func Init(cfg *setting.KafkaConfig) (err error) {
	address := []string{cfg.Address}
	chanSize := cfg.ChanSize
	config := sarama.NewConfig()
	// 发送完数据需要leader和follow都确认
	config.Producer.RequiredAcks = sarama.WaitForAll
	// 新选出一个partition
	config.Producer.Partitioner = sarama.NewHashPartitioner
	// 成功交付的消息将在success channel返回
	config.Producer.Return.Successes = true

	client, err = sarama.NewSyncProducer(address, config)
	if err != nil {
		fmt.Println("producer closed,err", err)
		return
	}

	msgChan = make(chan *sarama.ProducerMessage, chanSize)

	//后台goroutine从msgChan中读数据，发送给kafka
	go sendMsg()

	return
}

// 从通道MsgChan中读取msg，发送给kafka
func sendMsg() {
	for {
		select {
		case msg := <-msgChan:
			pid, offset, err := client.SendMessage(msg)
			if err != nil {
				fmt.Printf("send msg failed,err:%v\n", err)
				return
			}
			fmt.Printf("send msg to kafka success,pid:%d offset:%d", pid, offset)

		}
	}
}

// 定义一个函数向外暴露msgChan 单向通道 只能写入值 不能读取值
func ToMsgChan(msg *sarama.ProducerMessage) {
	msgChan <- msg
}
