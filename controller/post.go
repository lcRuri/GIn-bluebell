package controller

import (
	"bluebell/logic"
	"bluebell/models"
	"strconv"

	"github.com/gin-gonic/gin"
	"go.uber.org/zap"
)

func CreatePostHandler(c *gin.Context) {

	//获取参数
	p := new(models.Post)
	err := c.ShouldBindJSON(p)
	if err != nil {
		zap.L().Error("CreatePostHandler failed,", zap.Error(err))
		ResponseError(c, CodeServerBusy)
		return
	}

	//从c中获取当前用户ID
	userID, err := getCurrentUserID(c)
	if err != nil {
		ResponseError(c, CodeNeedLogin)
		return
	}
	p.AuthorID = userID
	//创建帖子
	if err := logic.CreatePost(p); err != nil {
		zap.L().Error("CreatePost failed", zap.Error(err))
		ResponseError(c, CodeServerBusy)
		return
	}

	//返回响应
	ResponseSuccess(c, nil)
}

func GetPostDetailHandler(c *gin.Context) {
	pidStr := c.Param("id")
	pid, err := strconv.ParseInt(pidStr, 10, 64)
	if err != nil {
		zap.L().Error("get post detail with invalid param", zap.Error(err))
		ResponseError(c, CodeServerBusy)
		return
	}
	data, err := logic.GetPostById(pid)
	if err != nil {
		zap.L().Error("logic.GetPostById(pid) failed", zap.Error(err))
		ResponseError(c, CodeServerBusy)
		return
	}

	ResponseSuccess(c, data)
}

//GetPostListHandler 获取帖子列表的处理函数
func GetPostListHandler(c *gin.Context) {
	//获取分页参数
	page, size := GetPageInfo(c)
	//获取数据
	data, err := logic.GetPostList(page, size)
	if err != nil {
		zap.L().Error("GetPostListHandler failed", zap.Error(err))
		ResponseError(c, CodeServerBusy)
		return
	}
	//返回响应
	ResponseSuccess(c, data)
}

//GetPostListHandler2 升级版帖子列表接口
//根据前端传递的参数动态的获取帖子列表
//按创建时间 或者 分数排序
//1.获取参数
//2.去redis查询id信息
//3.根据id去数据库查询帖子详细详细
func GetPostListHandler2(c *gin.Context) {
	//获取分页参数
	//初始化结构体时指定参数
	p := &models.ParamPostList{
		Page:  1,
		Size:  10,
		Order: models.OrderTime,
	}
	if err := c.ShouldBindQuery(p); err != nil {
		zap.L().Error("ShouldBindQuery failed", zap.Error(err))
		ResponseError(c, CodeInvalidParam)
		return
	}

	//更新
	data, err := logic.GetPostListNew(p)

	if err != nil {
		zap.L().Error("GetPostListHandler failed", zap.Error(err))
		ResponseError(c, CodeServerBusy)
		return
	}
	//返回响应
	ResponseSuccess(c, data)
}

////GetCommunityPostListHandler 根据社区去查询帖子列表
//func GetCommunityPostListHandler(c *gin.Context) {
//	//初始化结构体时指定参数
//	p := &models.ParamCommunityPostList{
//		ParamPostList: &models.ParamPostList{
//			Page:  1,
//			Size:  10,
//			Order: models.OrderTime,
//		},
//	}
//	if err := c.ShouldBindQuery(p); err != nil {
//		zap.L().Error("GetCommunityPostListHandler failed", zap.Error(err))
//		ResponseError(c, CodeInvalidParam)
//		return
//	}
//
//	//获取数据
//
//	if err != nil {
//		zap.L().Error("GetPostListHandler failed", zap.Error(err))
//		ResponseError(c, CodeServerBusy)
//		return
//	}
//	//返回响应
//	ResponseSuccess(c, data)
//}
