package logic

import (
	"bluebell/dao/mysql"
	"bluebell/models"
	"bluebell/pkg/jwt"
	"bluebell/pkg/snowflake"
)

func SignUp(p *models.ParamsSignUp) (err error) {
	err = mysql.CheckUserExist(p.Username)
	if err != nil {
		return err
	}

	//2.生成UID
	userID := snowflake.GetID()
	//3.存入数据库
	user := &models.User{
		UserId:   userID,
		Username: p.Username,
		Password: p.Password,
	}
	return mysql.InsertUser(user)

}

func Login(p *models.ParamsLogin) (user *models.User, err error) {
	user = &models.User{
		Username: p.Username,
		Password: p.Password,
	}
	err = mysql.Login(user)
	if err != nil {
		return nil, err
	}
	token, err := jwt.GenToken(user.UserId, user.Username)
	if err != nil {
		return
	}
	user.Token = token
	return
}
