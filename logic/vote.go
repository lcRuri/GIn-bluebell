package logic

import (
	"bluebell/dao/redis"
	"bluebell/models"
	"strconv"

	"go.uber.org/zap"
)

/* 投票的几种情况
direction=1
	1.之前没有投过票，现在要投赞成票
	2.之前投反对票，现在改投赞成票
direction=0
	1.之前投赞成票，现在要取消投票
	2.之前投反对票，现要在取消投票
direction=-1
	1.之前没有投过票，现在要投反对票
	2.之前投赞成票，现在改投反对票
*/
func PostForVote(userID int64, p *models.ParamsVoteData) error {
	zap.L().Debug("VoteForPost", zap.Int64("userID", userID), zap.String("postID", p.PostID), zap.Int8("direction", p.Direction))
	return redis.VoteForPost(strconv.Itoa(int(userID)), p.PostID, float64(p.Direction))

}
