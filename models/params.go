package models

const (
	OrderTime  = "time"
	OrderScore = "score"
)

type ParamsSignUp struct {
	Username   string `json:"username" binding:"required"`
	Password   string `json:"password" binding:"required"`
	RePassword string `json:"re_password" binding:"required,eqfield=Password"`
}

type ParamsLogin struct {
	Username string `json:"username" binding:"required"`
	Password string `json:"password" binding:"required"`
}

//投票
type ParamsVoteData struct {
	PostID    string `json:"post_id" binding:"required"`              //贴子id
	Direction int8   `json:"direction,string" binding:"oneof=1 0 -1"` //赞成话说反对 1赞成 -1反对
}

type ParamPostList struct {
	CommunityID int64  `json:"community_id" form:"community_id"` //可以为空
	Page        int64  `json:"page" form:"page"`
	Size        int64  `json:"size" form:"size"`
	Order       string `json:"order" form:"order"`
}
