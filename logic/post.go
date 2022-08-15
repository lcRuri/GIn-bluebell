package logic

import (
	"bluebell/dao/mysql"
	"bluebell/dao/redis"
	"bluebell/models"
	"bluebell/pkg/snowflake"

	"go.uber.org/zap"
)

func CreatePost(p *models.Post) (err error) {
	//生成postID
	p.ID = snowflake.GetID()
	//保存到数据库
	err = mysql.CreatePost(p)
	if err != nil {
		return err
	}
	err = redis.CreatePost(p.ID, p.CommunityID)
	if err != nil {
		return err
	}
	return
}

func GetPostById(pid int64) (data *models.ApiPostDetail, err error) {

	post, err := mysql.GetPostById(pid)
	if err != nil {
		zap.L().Error("mysql.GetPostById(pid) failed", zap.Error(err))
		return
	}

	//根据id查询作者信息
	user, err := mysql.GetUserById(post.AuthorID)
	if err != nil {
		zap.L().Error("mysql.GetUserById(post.AuthorID) failed", zap.Error(err))
		return
	}

	//根据id查询社区详细信息
	community, err := mysql.GetCommunityDetailByID(post.CommunityID)
	if err != nil {
		zap.L().Error("mysql.GetCommunityDetailByID(post.CommunityID) failed", zap.Error(err))
		return
	}

	data = &models.ApiPostDetail{
		AuthorName:      user.Username,
		Post:            post,
		CommunityDetail: community,
	}
	return
}

//GetPostList 获取帖子列表
func GetPostList(page, size int64) (data []*models.ApiPostDetail, err error) {
	posts, err := mysql.GetPostList(page, size)
	if err != nil {
		return nil, err
	}
	data = make([]*models.ApiPostDetail, 0, len(posts))
	for _, post := range posts {
		//根据id查询作者信息
		user, err := mysql.GetUserById(post.AuthorID)
		if err != nil {
			zap.L().Error("mysql.GetUserById(post.AuthorID) failed", zap.Error(err))
			continue
		}

		//根据id查询社区详细信息
		community, err := mysql.GetCommunityDetailByID(post.CommunityID)
		if err != nil {
			zap.L().Error("mysql.GetCommunityDetailByID(post.CommunityID) failed", zap.Error(err))
			continue
		}

		postDetail := &models.ApiPostDetail{
			AuthorName:      user.Username,
			Post:            post,
			CommunityDetail: community,
		}

		data = append(data, postDetail)
	}
	return
}

func GetPostList2(p *models.ParamPostList) (data []*models.ApiPostDetail, err error) {
	//2.去redis查询id信息
	ids, err := redis.GetPostIDInOrder(p)
	if err != nil {
		zap.L().Error("redis.GetPostIDInOrder(p) failed", zap.Error(err))
		return
	}
	if len(ids) == 0 {
		zap.L().Warn("redis.GetPostIDInOrder success return 0 data")
		return
	}
	zap.L().Debug("GetPostList2", zap.Any("ids", ids))
	//3.根据id去数据库查询帖子详细详细
	//返回的数据还要按照给定的id的顺序返回
	posts, err := mysql.GetPostListByIDs(ids)
	if err != nil {
		return
	}
	zap.L().Debug("mysql.GetPostListByIDs(ids)", zap.Any("posts", posts))
	//提前查询好每篇帖子的投票数
	voteData, err := redis.GetPostVoteData(ids)
	if err != nil {
		return
	}
	//根据posts中的数据查询作者和分区信息
	data = make([]*models.ApiPostDetail, 0, len(posts))
	for idx, post := range posts {
		//根据id查询作者信息
		user, err := mysql.GetUserById(post.AuthorID)
		if err != nil {
			zap.L().Error("mysql.GetUserById(post.AuthorID) failed", zap.Error(err))
			continue
		}

		//根据id查询社区详细信息
		community, err := mysql.GetCommunityDetailByID(post.CommunityID)
		if err != nil {
			zap.L().Error("mysql.GetCommunityDetailByID(post.CommunityID) failed", zap.Error(err))
			continue
		}

		postDetail := &models.ApiPostDetail{
			AuthorName:      user.Username,
			VoteNum:         voteData[idx],
			Post:            post,
			CommunityDetail: community,
		}

		data = append(data, postDetail)
	}
	return

}

func GetCommunityPostList(p *models.ParamPostList) (data []*models.ApiPostDetail, err error) {

	//2.去redis查询id信息
	ids, err := redis.GetCommunityPostIDInOrder(p)
	if err != nil {
		zap.L().Error("redis.GetPostIDInOrder(p) failed", zap.Error(err))
		return
	}
	if len(ids) == 0 {
		zap.L().Warn("redis.GetPostIDInOrder success return 0 data")
		return
	}
	zap.L().Debug("GetCommunityPostList2", zap.Any("ids", ids))

	//3.根据id去数据库查询帖子详细详细
	//返回的数据还要按照给定的id的顺序返回
	posts, err := mysql.GetPostListByIDs(ids)
	if err != nil {
		return
	}
	zap.L().Debug("mysql.GetPostListByIDs(ids)", zap.Any("posts", posts))
	//提前查询好每篇帖子的投票数
	voteData, err := redis.GetPostVoteData(ids)
	if err != nil {
		return
	}
	//根据posts中的数据查询作者和分区信息
	data = make([]*models.ApiPostDetail, 0, len(posts))
	for idx, post := range posts {
		//根据id查询作者信息
		user, err := mysql.GetUserById(post.AuthorID)
		if err != nil {
			zap.L().Error("mysql.GetUserById(post.AuthorID) failed", zap.Error(err))
			continue
		}

		//根据id查询社区详细信息
		community, err := mysql.GetCommunityDetailByID(post.CommunityID)
		if err != nil {
			zap.L().Error("mysql.GetCommunityDetailByID(post.CommunityID) failed", zap.Error(err))
			continue
		}

		postDetail := &models.ApiPostDetail{
			AuthorName:      user.Username,
			VoteNum:         voteData[idx],
			Post:            post,
			CommunityDetail: community,
		}

		data = append(data, postDetail)
	}
	return
}

//GetPostListNew 将两个帖子列表查询合二为一的函数
func GetPostListNew(p *models.ParamPostList) (data []*models.ApiPostDetail, err error) {
	if p.CommunityID == 0 {
		//查询所有
		data, err = GetPostList2(p)
	} else {
		//根据社区id查询
		data, err = GetCommunityPostList(p)
	}

	if err != nil {
		zap.L().Error("GetPostListNew failed", zap.Error(err))
		return
	}

	return
}
