package redis

import (
	"bluebell/models"
	"strconv"
	"time"

	"github.com/go-redis/redis"
)

func getIDsFromKey(key string, page, size int64) ([]string, error) {
	//2.确定查询索引的起始点
	start := (page - 1) * size
	end := start + size - 1
	//3.ZREVRANGE 按分数从大到小查询指定数量的元素
	return client.ZRevRange(key, start, end).Result()
}

func GetPostIDInOrder(p *models.ParamPostList) ([]string, error) {
	//从redis获取id
	key := getRedisKey(KeyPostTimeZSet)
	if p.Order == models.OrderScore {
		//根据用户请求中携带的order参数确定要查询的redis的key
		key = getRedisKey(KeyPostScoreZSet)
	}
	return getIDsFromKey(key, p.Page, p.Size)
}

//GetPostVoteData 根据ids查询每篇帖子的投票的数据
func GetPostVoteData(ids []string) (data []int64, err error) {
	data = make([]int64, 0, len(ids))
	//for _, id := range ids {
	//	key := getRedisKey(KeyPostVotedZSetPrefix + id)
	//	//查找key中分数是1元素的数量->统计每篇帖子赞助票的数量
	//	v := client.ZCount(key, "1", "1").Val()
	//	data = append(data, v)
	//}

	//使用pipeline一次发送多条命令减少RTT
	pipeline := client.Pipeline()
	for _, id := range ids {
		key := getRedisKey(KeyPostVotedZSetPrefix + id)
		pipeline.ZCount(key, "1", "1")
	}
	cmders, err := pipeline.Exec()
	if err != nil {
		return nil, err
	}

	data = make([]int64, 0, len(cmders))
	for _, cmder := range cmders {
		v := cmder.(*redis.IntCmd).Val()
		data = append(data, v)
	}

	return
}

//GetCommunityPostIDInOrder 按社区查询ids
func GetCommunityPostIDInOrder(p *models.ParamPostList) ([]string, error) {

	//从redis获取id
	orderKey := getRedisKey(KeyPostTimeZSet)
	if p.Order == models.OrderScore {
		//根据用户请求中携带的order参数确定要查询的redis的key
		orderKey = getRedisKey(KeyPostScoreZSet)
	}

	//使用zinterstore 把分区的帖子set与帖子分数的zset 生成员工新的zset
	//即将社区分类与得分两者postID一样的的帖子数据形成新的zset

	//社区的key
	cKey := getRedisKey(KeyCommunitySetPrefix + strconv.Itoa(int(p.CommunityID)))

	//利用缓存key减少zinterstore执行的次数
	key := orderKey + strconv.Itoa(int(p.CommunityID))
	if client.Exists(key).Val() < 1 {
		//不存在，需要计算
		pipeline := client.Pipeline()
		pipeline.ZInterStore(key, redis.ZStore{
			Aggregate: "MAX",
		}, cKey, orderKey) //zinterstore 计算
		pipeline.Expire(key, 60*time.Second) //设置超时时间
		_, err := pipeline.Exec()
		if err != nil {
			return nil, err
		}
	}

	//存在的话就直接根据key查询ids
	return getIDsFromKey(key, p.Page, p.Size)

}
