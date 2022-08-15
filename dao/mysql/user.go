package mysql

import (
	"bluebell/models"
	"crypto/md5"
	"database/sql"
	"encoding/hex"

	"go.uber.org/zap"
)

const secret = "xuanye"

func CheckUserExist(username string) (err error) {
	sqlStr := "select count(user_id) from user where username = ?"
	var count int
	if err = db.Get(&count, sqlStr, username); err != nil {
		return err
	}
	if count > 0 {
		return ErrorUserExist
	}
	return
}

func InsertUser(user *models.User) (err error) {
	//对密码进行加密
	password := EncryptPassword(user.Password)
	//插入注册用户数据
	sqlStr := "insert into user(user_id,username,password) values(?,?,?)"
	_, err = db.Exec(sqlStr, user.UserId, user.Username, password)
	return
}

func Login(user *models.User) (err error) {
	oPassword := user.Password
	strSql := "select user_id,username,password from user where username = ?"

	err = db.Get(user, strSql, user.Username)
	if err == sql.ErrNoRows {
		return ErrorUserNotExist
	}
	if err != nil {
		return err
	}
	//判断输入的密码是否一样
	if EncryptPassword(oPassword) != user.Password {
		zap.L().Error("密码错误，请重新输入")
		return ErrorInvalidPassword
	}
	return
}

func EncryptPassword(oPassword string) string {
	h := md5.New()
	h.Write([]byte(secret))
	return hex.EncodeToString(h.Sum([]byte(oPassword)))
}

func GetUserById(uid int64) (user *models.User, err error) {
	user = new(models.User)
	sqlStr := "select username username from user where user_id = ?"
	db.Get(user, sqlStr, uid)
	return

}
