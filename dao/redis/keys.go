package redis

//redis key
const (
	KeyPrefix              = "bluebell:"
	KeyPostTimeZSet        = "post:time"   //贴子及发帖时间
	KeyPostScoreZSet       = "post:score"  //贴子及投票分数
	KeyPostVotedZSetPrefix = "post:voted:" //记录用户投票类型;参数时post_id
	KeyCommunitySetPrefix  = "community:"  //保存每个分区下帖子的id

)

//给redis key加上前缀
func getRedisKey(key string) string {
	return KeyPrefix + key
}
