package redis

import (
	"errors"
	"math"
	"strconv"
	"time"

	"go.uber.org/zap"

	"github.com/go-redis/redis"
)

const (
	oneWeekInSecond = 7 * 24 * 3600
	scorePerVote    = 432
)

var (
	ErrVoteTimeExpire = errors.New("投票时间已过")
	ErrVoteRepeated   = errors.New("不允许重复投票")
)

func VoteForPost(userID, postID string, value float64) error {
	//1、判断投票限制
	//去redis取帖子发布时间
	postTime := client.ZScore(getRedisKey(KeyPostTimeZSet), postID).Val()
	if float64(time.Now().Unix())-postTime > oneWeekInSecond {
		zap.L().Debug("postTime:", zap.Float64("postTime", postTime))
		return ErrVoteTimeExpire
	}
	//2和3需要放到员工事务里面去

	//2、更新帖子的分数
	//先查当前用户给当前帖子的投票记录
	ov := client.ZScore(getRedisKey(KeyPostVotedZSetPrefix+postID), userID).Val()

	//如果这次投票的值和原来一致，则不允许投票
	if value == ov {
		return ErrVoteRepeated
	}
	var op float64
	if value > ov {
		op = 1
	} else {
		op = -1
	}
	diff := math.Abs(ov - value) //计算两次投票的差值
	pipeline := client.TxPipeline()
	pipeline.ZIncrBy(getRedisKey(KeyPostScoreZSet), op*diff*scorePerVote, postID)

	//3、记录用户为该帖子投票的数据
	if value == 0 {
		pipeline.ZRem(getRedisKey(KeyPostVotedZSetPrefix+postID), userID).Result()
	} else {
		pipeline.ZAdd(getRedisKey(KeyPostVotedZSetPrefix+postID), redis.Z{
			Score:  value, //当前用户是赞成还是反对
			Member: userID,
		})
	}
	_, err := pipeline.Exec()

	return err

}

func CreatePost(postID, communityID int64) error {
	pipeline := client.TxPipeline()
	//帖子时间
	pipeline.ZAdd(getRedisKey(KeyPostTimeZSet), redis.Z{
		Score:  float64(time.Now().Unix()),
		Member: postID,
	})

	//帖子分数
	pipeline.ZAdd(getRedisKey(KeyPostScoreZSet), redis.Z{
		Score:  float64(time.Now().Unix()),
		Member: postID,
	})

	//更新：把帖子id加到社区的set
	cKey := getRedisKey(KeyCommunitySetPrefix + strconv.Itoa(int(communityID)))
	pipeline.SAdd(cKey, postID)

	_, err := pipeline.Exec()
	zap.L().Error("create post time", zap.Error(err))
	return err
}
