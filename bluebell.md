

# 开发文档

## Go Web 脚手架搭建

### 1.加载配置（viper）

编写配置文件.yml

通过go get命令获取viper

```bash
go get github.com/spf13/viper
```

编写读取配置文件settings.go

通过settings.go用viper读取配置文件

```
func Init() (err error) {
   
   viper.SetConfigName("config") // 指定配置文件名（不带后缀）
  
   viper.AddConfigPath("./conf") // 指定查找配置文件的路径（这里使用相对路径）

  
   err = viper.ReadInConfig() // 读取配置信息
   if err != nil {
      // 读取配置信息失败
      fmt.Printf("viper.ReadInConfig failed, err:%v\n", err)
      return
   }

   // 把读取到的配置信息反序列化到 Conf 变量中
   if err := viper.Unmarshal(Conf); err != nil {
      fmt.Printf("viper.Unmarshal failed, err:%v\n", err)
   }

   viper.WatchConfig()
   viper.OnConfigChange(func(in fsnotify.Event) {
      fmt.Println("配置文件修改了...")
      if err := viper.Unmarshal(Conf); err != nil {
         fmt.Printf("viper.Unmarshal failed, err:%v\n", err)
      }
   })
   return
}
```

### 2.编写logger

通过viper读取配置文件中的logger配置

```
package logger

import (
   "net"
   "net/http"
   "net/http/httputil"
   "os"
   "runtime/debug"
   "strings"
   "time"

   "github.com/spf13/viper"

   "github.com/gin-gonic/gin"
   "github.com/natefinch/lumberjack"
   "go.uber.org/zap"
   "go.uber.org/zap/zapcore"
)

// InitLogger 初始化Logger
func Init() (err error) {
   writeSyncer := getLogWriter(
      viper.GetString("log.filename"),
      viper.GetInt("log.max_Size"),
      viper.GetInt("log.max_backups"),
      viper.GetInt("log.max_age"))
   encoder := getEncoder()
   var l = new(zapcore.Level)
   err = l.UnmarshalText([]byte(viper.GetString("log.level")))
   if err != nil {
      return
   }
   core := zapcore.NewCore(encoder, writeSyncer, l)

   lg := zap.New(core, zap.AddCaller())
   zap.ReplaceGlobals(lg) // 替换zap包中全局的logger实例，后续在其他包中只需使用zap.L()调用即可
   return
}

func getEncoder() zapcore.Encoder {
   encoderConfig := zap.NewProductionEncoderConfig()
   encoderConfig.EncodeTime = zapcore.ISO8601TimeEncoder
   encoderConfig.TimeKey = "time"
   encoderConfig.EncodeLevel = zapcore.CapitalLevelEncoder
   encoderConfig.EncodeDuration = zapcore.SecondsDurationEncoder
   encoderConfig.EncodeCaller = zapcore.ShortCallerEncoder
   return zapcore.NewJSONEncoder(encoderConfig)
}

func getLogWriter(filename string, maxSize, maxBackup, maxAge int) zapcore.WriteSyncer {
   lumberJackLogger := &lumberjack.Logger{
      Filename:   filename,
      MaxSize:    maxSize,
      MaxBackups: maxBackup,
      MaxAge:     maxAge,
   }
   return zapcore.AddSync(lumberJackLogger)
}

// GinLogger 接收gin框架默认的日志
func GinLogger() gin.HandlerFunc {
   return func(c *gin.Context) {
      start := time.Now()
      path := c.Request.URL.Path
      query := c.Request.URL.RawQuery
      c.Next()

      cost := time.Since(start)
      zap.L().Info(path,
         zap.Int("status", c.Writer.Status()),
         zap.String("method", c.Request.Method),
         zap.String("path", path),
         zap.String("query", query),
         zap.String("ip", c.ClientIP()),
         zap.String("user-agent", c.Request.UserAgent()),
         zap.String("errors", c.Errors.ByType(gin.ErrorTypePrivate).String()),
         zap.Duration("cost", cost),
      )
   }
}

// GinRecovery recover掉项目可能出现的panic，并使用zap记录相关日志
func GinRecovery(stack bool) gin.HandlerFunc {
   return func(c *gin.Context) {
      defer func() {
         if err := recover(); err != nil {
            // Check for a broken connection, as it is not really a
            // condition that warrants a panic stack trace.
            var brokenPipe bool
            if ne, ok := err.(*net.OpError); ok {
               if se, ok := ne.Err.(*os.SyscallError); ok {
                  if strings.Contains(strings.ToLower(se.Error()), "broken pipe") || strings.Contains(strings.ToLower(se.Error()), "connection reset by peer") {
                     brokenPipe = true
                  }
               }
            }

            httpRequest, _ := httputil.DumpRequest(c.Request, false)
            if brokenPipe {
               zap.L().Error(c.Request.URL.Path,
                  zap.Any("error", err),
                  zap.String("request", string(httpRequest)),
               )
               // If the connection is dead, we can't write a status to it.
               c.Error(err.(error)) // nolint: errcheck
               c.Abort()
               return
            }

            if stack {
               zap.L().Error("[Recovery from panic]",
                  zap.Any("error", err),
                  zap.String("request", string(httpRequest)),
                  zap.String("stack", string(debug.Stack())),
               )
            } else {
               zap.L().Error("[Recovery from panic]",
                  zap.Any("error", err),
                  zap.String("request", string(httpRequest)),
               )
            }
            c.AbortWithStatus(http.StatusInternalServerError)
         }
      }()
      c.Next()
   }
}
```

### 3.初始化日志、mysql连接、redis

#### mysql

```
func Init(cfg *setting.MySQLConfig) (err error) {
   dsn := fmt.Sprintf("%s:%s@tcp(%s:%d)/%s?charset=utf8mb4&parseTime=True&loc=Local",
      //viper.GetString("mysql.user"),
      //viper.GetString("mysql.password"),
      //viper.GetString("mysql.host"),
      //viper.GetInt("mysql.port"),
      //viper.GetString("mysql.dbname"))
      cfg.User,
      cfg.Password,
      cfg.Host,
      cfg.Port,
      cfg.DB)
   // 也可以使用MustConnect连接不成功就panic
   db, err = sqlx.Connect("mysql", dsn)
   if err != nil {
      zap.L().Error("connect DB failed", zap.Error(err))
      return
   }
   db.SetMaxOpenConns(cfg.MaxOpenConns)
   db.SetMaxIdleConns(cfg.MaxIdleConns)
   return
}
```

#### redis

```
// 初始化连接
func Init(cfg *setting.RedisConfig) (err error) {
   rdb = redis.NewClient(&redis.Options{
      Addr: fmt.Sprintf("%s:%d",
         //viper.GetString("redis.host"),
         //viper.GetInt("redis.port")),
         cfg.Host,
         cfg.Port),
      //Password: viper.GetString("redis.password"), // no password set
      //DB:       viper.GetInt("redis.db"),          // use default DB
      //PoolSize: viper.GetInt("redis.pool_size"),
      Password: cfg.Password, // no password set
      DB:       cfg.DB,       // use default DB
      PoolSize: cfg.PoolSize,
   })

   return
}
```

### 4.注册路由

```
func SetUp() *gin.Engine {
   gin.SetMode(gin.ReleaseMode)
   r := gin.New()
   r.Use(logger.GinLogger(), logger.GinRecovery(true))

 

   r.GET("/", func(c *gin.Context) {
      c.String(http.StatusOK, "ok")
   })

   return r
}
```

### 5.启动服务

```
func main() {
   //1.加载配置
   //2.初始化日志
   //3.初始化mysql连接
   //4.初始化redis连接
   //初始化gin框架内置的校验器使用的翻译器
   //5.注册路由
   //6.启动服务(优雅关机)
 
   }
```

## user项目数据库搭建

```
CREATE TABLE `user` (
                        `id` bigint(20) NOT NULL AUTO_INCREMENT,
                        `user_id` bigint(20) NOT NULL,
                        `username` varchar(64) COLLATE utf8mb4_general_ci NOT NULL,
                        `password` varchar(64) COLLATE utf8mb4_general_ci NOT NULL,
                        `email` varchar(64) COLLATE utf8mb4_general_ci,
                        `gender` tinyint(4) NOT NULL DEFAULT '0',
                        `create_time` timestamp NULL DEFAULT CURRENT_TIMESTAMP,
                        `update_time` timestamp NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE
                                    CURRENT_TIMESTAMP,
                        PRIMARY KEY (`id`),
                        UNIQUE KEY `idx_username` (`username`) USING BTREE,
                        UNIQUE KEY `idx_user_id` (`user_id`) USING BTREE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci
```

## 基于雪花算法的分布式ID

安装

```
 go get github.com/bwmarrin/snowflake
```

详细代码

```
package snowflake

import (
   "time"

   "github.com/bwmarrin/snowflake"
)

var node *snowflake.Node

func Init(startTime string, machineID int64) (err error) {
   var st time.Time
   st, err = time.Parse("2006-01-02", startTime)
   if err != nil {
      return
   }
   snowflake.Epoch = st.UnixNano() / 100000
   node, err = snowflake.NewNode(machineID)
   return
}

func GetID() int64 {
   return node.Generate().Int64()
}
```

## 注册业务

### 通过路由处理请求 routes

通过gin框架的*gin.Engine创建路由，注册请求为post，请求路径为signUp，具体处理交给controller层

```
r.POST("/signUp", controller.SignUpHandler)
```

### **controller**

注册请求流程

1. 获取参数和参数校验 

   在models中定义了注册需要参数的结构体ParamsSignUp,在controller层中创建注册需要的结构体

   ```
   type ParamsSignUp struct {
      Username   string `json:"username" binding:"required"`
      Password   string `json:"password" binding:"required"`
      RePassword string `json:"re_password" binding:"required,eqfield=Password"`
   }
   ```

   通过shouldBindJSON()函数配合结构体中的tag参数binding进行参数的校验

### **logic**

​	2.业务处理

​		调用logic层进行注册的具体业务，如下

```
func SignUp(p *models.ParamsSignUp) {
   //1.判断用户是否存在
   mysql.CheckUserExist()
   //2.生成UID
   snowflake.GetID()
   //3.存入数据库
   mysql.InsertUser()

}
```

### **dao mysql**

​	在mysql层首先接收logic层传输过来的p *models.ParamsSignUp参数，里面包含了所需的注册所需个人信息，

首先在mysql判断用户是否存在，如果存在，就终止注册，否则就插入用户数据，插入用户密码时，不能明文存入到数据库，需要将密码进行加密存入数据库，完成注册。

```
func CheckUserExist() {
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

func InsertUser() {
	//对密码进行加密
	password := EncryptPassword(user.Password)
	//插入注册用户数据
	sqlStr := "insert into user(user_id,username,password) values(?,?,?)"
	_, err = db.Exec(sqlStr, user.UserId, user.Username, password)
	return
}
```

## mode控制日志输出位置

在正常写开发时候，我们不想在一直通过.log文件查找日志，而是将日志输出到控制台，上线的时候记录到日志文件就行。

```
var core zapcore.Core
if mode == "dev" {
   //进入开发模式，日志输出到终端
   consoleEncoder := zapcore.NewConsoleEncoder(zap.NewDevelopmentEncoderConfig())
   core = zapcore.NewTee(
      zapcore.NewCore(encoder, writeSyncer, l),
      zapcore.NewCore(consoleEncoder, zapcore.Lock(os.Stdout), zapcore.DebugLevel),
   )
} else {
   core = zapcore.NewCore(encoder, writeSyncer, l)
}
```

## validator库参数校验

### 翻译校验错误提示信息

`validator`库本身是支持国际化的，借助相应的语言包可以实现校验错误提示信息的自动翻译

```go
// 定义一个全局翻译器T
var trans ut.Translator

// InitTrans 初始化翻译器
func InitTrans(locale string) (err error) {
	// 修改gin框架中的Validator引擎属性，实现自定制
	if v, ok := binding.Validator.Engine().(*validator.Validate); ok {

		zhT := zh.New() // 中文翻译器
		enT := en.New() // 英文翻译器

		// 第一个参数是备用（fallback）的语言环境
		// 后面的参数是应该支持的语言环境（支持多个）
		// uni := ut.New(zhT, zhT) 也是可以的
		uni := ut.New(enT, zhT, enT)

		// locale 通常取决于 http 请求头的 'Accept-Language'
		var ok bool
		// 也可以使用 uni.FindTranslator(...) 传入多个locale进行查找
		trans, ok = uni.GetTranslator(locale)
		if !ok {
			return fmt.Errorf("uni.GetTranslator(%s) failed", locale)
		}

		// 注册翻译器
		switch locale {
		case "en":
			err = enTranslations.RegisterDefaultTranslations(v, trans)
		case "zh":
			err = zhTranslations.RegisterDefaultTranslations(v, trans)
		default:
			err = enTranslations.RegisterDefaultTranslations(v, trans)
		}
		return
	}
	return
}
```



## 登录业务

### routes

通过gin框架的*gin.Engine创建路由，注册请求为post，请求路径为login，具体处理交给controller层

```
r.POST("/login", controller.LoginHandler)
```

### controller

获取参数和参数校验 

在models中定义了注册需要参数的结构体ParamsLogin,在controller层中创建注册需要的结构体

```
type ParamsLogin struct {
	Username   string `json:"username" binding:"required"`
	Password   string `json:"password" binding:"required"`
}
```

通过shouldBindJSON()函数配合结构体中的tag参数binding进行参数的校验

### logic

```
logic.Login(p)
```

调用logic层进行登录的具体业务，如下

在mysql层需要的结构体对应的是user，user结构体对应了数据库中的用户表，需要在logic中声明user传入mysql

```
func Login(p *models.ParamsLogin) (err error) {

  user := &models.User{
		Username: p.Username,
		Password: p.Password,
	}
	err = mysql.Login(user)
	if err != nil {
		return "", err
	}
	return jwt.GenToken(user.UserId, user.Username)
}
```

### mysql

```
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
```

## 定义状态码

为了给前端更好的显示信息，将各种错误进行封装，便于更好的展示信息。

### 定义返回信息

```
package controller

type ResCode int64

const (
   CodeSuccess ResCode = 1000 + iota
   CodeInvalidParam
   CodeUserExist
   CodeUserNotExist
   CodeInvalidPassword
   CodeServerBusy

   CodeInvalidToken
   CodeNeedLogin
)

var codeMsgMap = map[ResCode]string{
   CodeSuccess:         "success",
   CodeInvalidParam:    "请求参数错误",
   CodeUserExist:       "用户名已经存在",
   CodeUserNotExist:    "用户名不存在",
   CodeInvalidPassword: "用户名或密码错误",
   CodeServerBusy:      "服务繁忙",
   CodeNeedLogin:       "需要登录",
   CodeInvalidToken:    "无效的Token",
}

func (c ResCode) Msg() string {
   msg, ok := codeMsgMap[c]
   if !ok {
      msg = codeMsgMap[CodeServerBusy]
   }
   return msg
}
```

### 具体respone操作

```
type ResponseData struct {
   Code ResCode     `json:"code"`
   Msg  interface{} `json:"msg"`
   Data interface{} `json:"data"`
}

func ResponseError(c *gin.Context, code ResCode) {
   c.JSON(http.StatusOK, &ResponseData{
      Code: code,
      Msg:  code.Msg(),
      Data: nil,
   })
}

func ResponseErrorWithMsg(c *gin.Context, code ResCode, msg interface{}) {
   c.JSON(http.StatusOK, &ResponseData{
      Code: code,
      Msg:  msg,
      Data: nil,
   })
}

func ResponseSuccess(c *gin.Context, data interface{}) {

   c.JSON(http.StatusOK, &ResponseData{
      Code: CodeSuccess,
      Msg:  CodeSuccess.Msg(),
      Data: data,
   })
}
```

## JWT Token 中间件

JWT就是一种基于Token的轻量级认证模式，服务端认证通过后，会生成一个JSON对象，经过签名后得到一个Token（令牌）再发回给用户，用户后续请求只需要带上这个Token，服务端解密之后就能获取该用户的相关信息了。

我们在这里直接使用`jwt-go`这个库来实现我们生成JWT和解析JWT的功能。

### 定义需求

我们需要定制自己的需求来决定JWT中保存哪些数据，比如我们规定在JWT中要存储`username`信息，那么我们就定义一个`MyClaims`结构体如下：

```go
// MyClaims 自定义声明结构体并内嵌jwt.StandardClaims
// jwt包自带的jwt.StandardClaims只包含了官方字段
// 我们这里需要额外记录一个username字段，所以要自定义结构体
// 如果想要保存更多信息，都可以添加到这个结构体中
type MyClaims struct {
	Username string `json:"username"`
	jwt.StandardClaims
}
```

然后我们定义JWT的过期时间，这里以2小时为例：

```go
const TokenExpireDuration = time.Hour * 2
```

接下来还需要定义Secret：

```go
var MySecret = []byte("夏天夏天悄悄过去")
```

### 生成Token

```
//生成Token
func GenToken(userID int64, username string) (string, error) {
   c := MyClaims{
      UserID:   userID,
      Username: username,
      StandardClaims: jwt.StandardClaims{
         ExpiresAt: time.Now().Add(TokenExpireDuration).Unix(), //过期时间
         Issuer:    "bluebell",                                 //签发人

      },
   }
   //使用指定的签名方法创建对象
   token := jwt.NewWithClaims(jwt.SigningMethodHS256, c)
   //使用指定的secret签名并获得完整的编码后的字符串token
   return token.SignedString(mySecret)
}

```

### 解析jwt

```
func ParseToken(tokenString string) (*MyClaims, error) {
   //解析Token
   var mc = new(MyClaims)
   token, err := jwt.ParseWithClaims(tokenString, mc, func(token *jwt.Token) (i interface{}, err error) {
      return mySecret, nil
   })
   if err != nil {
      return nil, err
   }
   if token.Valid { // 校验token
      return mc, nil
   }
   return nil, errors.New("invalid token")
}
```

### 在gin框架中使用JWT

将jwt封装成一个中间件，通过use()方法

```
v1.Use(middlewares.JWTAuthMiddleware())
```

```
// JWTAuthMiddleware 基于JWT的认证中间件
func JWTAuthMiddleware() func(c *gin.Context) {
   return func(c *gin.Context) {
      // 客户端携带Token有三种方式 1.放在请求头 2.放在请求体 3.放在URI
      // 这里假设Token放在Header的Authorization中，并使用Bearer开头
      // 这里的具体实现方式要依据你的实际业务情况决定
      authHeader := c.Request.Header.Get("Authorization")
      if authHeader == "" {
         controller.ResponseError(c, controller.CodeNeedLogin)

         c.Abort()
         return
      }
      // 按空格分割
      parts := strings.SplitN(authHeader, " ", 2)
      if !(len(parts) == 2 && parts[0] == "Bearer") {
         controller.ResponseError(c, controller.CodeInvalidToken)

         c.Abort()
         return
      }
      // parts[1]是获取到的tokenString，我们使用之前定义好的解析JWT的函数来解析它
      mc, err := jwt.ParseToken(parts[1])
      if err != nil {
         controller.ResponseError(c, controller.CodeInvalidToken)

         c.Abort()
         return
      }
      // 将当前请求的username信息保存到请求的上下文c上
      c.Set(controller.ContextUserIDKey, mc.UserID)
      c.Next() // 后续的处理函数可以用过c.Get(ContextUserIDKey)来获取当前请求的用户信息
   }
}
```

将其他请求放到中间件下面，在访问其他请求时，必须经过jwt认证，即必须带上登录时的token才能访问

## community项目数据库搭建

```
DROP TABLE IF EXISTS `community`;
CREATE TABLE `community` (
     `id` int(11) NOT NULL AUTO_INCREMENT,
     `community_id` int(10) unsigned NOT NULL,
     `community_name` varchar(128) COLLATE utf8mb4_general_ci NOT NULL,
     `introduction` varchar(256) COLLATE utf8mb4_general_ci NOT NULL,
     `create_time` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP,
     `update_time` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
     PRIMARY KEY (`id`),
     UNIQUE KEY `idx_community_id` (`community_id`),
     UNIQUE KEY `idx_community_name` (`community_name`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;


INSERT INTO `community` VALUES ('1', '1', 'Go', 'Golang', '2016-11-01 08:10:10', '2016-11-01 08:10:10');
INSERT INTO `community` VALUES ('2', '2', 'leetcode', '刷题刷题刷题', '2020-01-01 08:00:00', '2020-01-01 08:00:00');
INSERT INTO `community` VALUES ('3', '3', 'CS:GO', 'Rush B。。。', '2018-08-07 08:30:00', '2018-08-07 08:30:00');
INSERT INTO `community` VALUES ('4', '4', 'LOL', '欢迎来到英雄联盟!', '2016-01-01 08:00:00', '2016-01-01 08:00:00');
```

## models

定义对应的结构体

```
package models

import "time"

type Community struct {
   ID   int64  `json:"id" db:"community_id"`
   Name string `json:"name" db:"community_name"`
}

type CommunityDetail struct {
   ID           int64     `json:"id" db:"community_id"`
   Name         string    `json:"name" db:"community_name"`
   Introduction string    `json:"introduction,omitempty" db:"introduction"`
   CreateTime   time.Time `json:"create_time" db:"create_time"`
}
```

## 社区(类别)分类查询

### routes

```
v1.GET("/community", controller.CommunityHandler)
```

### controller

调用logic层的得到社区列表处理函数，将数据以列表形式返回

```go
//查询到所有的社区(community_id,community_name)以列表形式返回
data, err := logic.GetCommunityList()
```

### logic

```go
//查询数据库 id name
return mysql.GetCommunityList()

返回值为[]*models.Community, error
```

### mysql

sql语句

```mysql
sqlStr := "select community_id, community_name from community"
```

## 社区(类别)分类查询(按照前端传过来的id)

### routes

```
v1.GET("/community/:id", controller.CommunityDetailHandler)
```

### controller

```
//1.获取社区id
idStr := c.Param("id")
```

调用logic层

```
logic.GetCommunityDetail(id)
```

### logic

```
eturn mysql.GetCommunityDetailByID(id)
```

### mysql

sql语句

```mysql
sqlStr := "select community_id, community_name, introduction, create_time from community where community_id = ?"
```

## 帖子(文章)创建

### routes

```
v1.POST("post", controller.CreatePostHandler)
```

### controller

通过new新建结构体接收前端传过来的数据

```
//获取参数
p := new(models.Post)
```

调用logic层

```
logic.CreatePost(p)
```

### logic

```
//生成postID
```

```
mysql.CreatePost(p)
```

同时将数据生成到redis中

```
redis.CreatePost(p.ID, p.CommunityID)
```

### mysql

sql语句

```
sqlStr := "insert into post (post_id,title,content,author_id,community_id) values (?,?,?,?,?)"
```

## 帖子(文章)详细查询

### routes

```
v1.GET("post/:id", controller.GetPostDetailHandler)
```

### controller

获取前端传来的参数

```
pidStr := c.Param("id")
```

调用logic层

```
logic.GetPostById(pid)
```

### logic

```
mysql.GetPostById(pid)
```

同时根据post中的authorID和CommunityID数据查询post对应的作者和社区信息

```
data = &models.ApiPostDetail{
   AuthorName:      user.Username,
   Post:            post,
   CommunityDetail: community,
}
```

### mysql

sql语句

```
sqlStr := "select post_id,title,content,author_id,community_id,create_time from post where post_id=?"
```

## 帖子(文章)详细分页展示

### routes

```
v1.GET("posts", controller.GetPostListHandler)
```

### controller

获取分页参数 page和size

```
//获取分页参数
pageStr := c.Query("page")
sizeStr := c.Query("size")
```

获取数据

```
//获取数据
data, err := logic.GetPostList(page, size)
```

### logic

```
posts, err := mysql.GetPostList(page, size)
```

### mysql

```
sqlStr := "select post_id,title,content,author_id,community_id,create_time from post limit ?,?"
```

```
err = db.Select(&posts, sqlStr, (page-1)*size, size)
```

## 帖子投票功能

### routes

```
v1.POST("/vote", controller.PostVote)
```

### controller

获取投票的参数

**ParamsVote**

```
type ParamsVoteData struct {
   PostID    string `json:"post_id" binding:"required"`              //贴子id
   Direction int8   `json:"direction,string" binding:"oneof=1 0 -1"` //赞成话说反对 1赞成 -1反对
}
```

```
//参数校验
p := new(models.ParamsVoteData)
```

通过getCurrentUserID(c)得到当前登录用户的id

调用logic

```
logic.PostForVote(id, p)
```

### logic

```
redis.VoteForPost(strconv.Itoa(int(userID)), p.PostID, float64(p.Direction))
```

### redis

取出帖子的发布时间，如果时间超过了一周，则无法对帖子进行投票

```
//1、判断投票限制
//去redis取帖子发布时间
postTime := client.ZScore(getRedisKey(KeyPostTimeZSet), postID).Val()
```

查看原来用户对帖子的投票direction

```
//先查当前用户给当前帖子的投票记录
ov := client.ZScore(getRedisKey(KeyPostVotedZSetPrefix+postID), userID).Val()
```

如果这次投票的值和原来一致，则不允许投票

否则计算两次投票的差值，再乘以scorePerVote得到分数

```
if value > ov {
   op = 1
} else {
   op = -1
}
diff := math.Abs(ov - value) //计算两次投票的差值
pipeline := client.TxPipeline()
pipeline.ZIncrBy(getRedisKey(KeyPostScoreZSet), op*diff*scorePerVote, postID)
```

记录用户为该帖子投票的数据

```
//3、
if value == 0 {
   pipeline.ZRem(getRedisKey(KeyPostVotedZSetPrefix+postID), userID).Result()
} else {
   pipeline.ZAdd(getRedisKey(KeyPostVotedZSetPrefix+postID), redis.Z{
      Score:  value, //当前用户是赞成还是反对
      Member: userID,
   })
}
_, err := pipeline.Exec()
```

## GetPostListHandler2 升级版帖子列表接口（按照分数还是时间查询帖子并排序）

### routes

```
v1.GET("/posts2", controller.GetPostListHandler2)
```

### controller

```
//获取分页参数
//初始化结构体时指定参数
p := &models.ParamPostList{
   Page:  1,
   Size:  10,
   Order: models.OrderTime,
}
```

logic

```
//更新
data, err := logic.GetPostListNew(p)
```

### logic

```
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
```

按照分数排序

首先取redis查询现有的所有帖子的id

```
//2.去redis查询id信息
ids, err := redis.GetPostIDInOrder(p)
```

### 按照分数

#### redis

如果传递过来的结构体参数里面的Order没有，则默认按照时间取出key，如果p.Order存在，则按照分数取出现有的所有key

```
func GetPostIDInOrder(p *models.ParamPostList) ([]string, error) {
   //从redis获取id
   key := getRedisKey(KeyPostTimeZSet)
   if p.Order == models.OrderScore {
      //根据用户请求中携带的order参数确定要查询的redis的key
      key = getRedisKey(KeyPostScoreZSet)
   }
   return getIDsFromKey(key, p.Page, p.Size)
}
```

其中返回调用了getIDsFromKey，利用redis中zset的特性将id数据按从大到小的规则返回

```
//3.ZREVRANGE 按分数从大到小查询指定数量的元素
return client.ZRevRange(key, start, end).Result()
```

同时还要查询每篇帖子的投票数

```
func GetPostVoteData(ids []string) (data []int64, err error) {
   data = make([]int64, 0, len(ids))
   //for _, id := range ids {
   // key := getRedisKey(KeyPostVotedZSetPrefix + id)
   // //查找key中分数是1元素的数量->统计每篇帖子赞助票的数量
   // v := client.ZCount(key, "1", "1").Val()
   // data = append(data, v)
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
```

#### mysql

通过redis中按顺序拿到的post的id数据，去mysql中查询帖子详情

```
posts, err := mysql.GetPostListByIDs(ids)
```

```
//GetPostListByIDs 根据给定的id列表查询数据
func GetPostListByIDs(ids []string) (postList []*models.Post, err error) {
   sqlStr := `select post_id,title,content,author_id,community_id,create_time 
   from post 
   where post_id in (?)
   order by FIND_IN_SET(post_id,?)`

   query, args, err := sqlx.In(sqlStr, ids, strings.Join(ids, ","))
   if err != nil {
      return nil, err
   }
   query = db.Rebind(query)

   err = db.Select(&postList, query, args...) //!!!!!
   if err != nil {
      return nil, err
   }
   return
}
```

根据posts中的数据查询作者和分区信息

### 按照社区

#### redis

如果传递过来的结构体参数里面的Order没有，则默认按照时间取出key，如果p.Order存在，则按照分数取出现有的所有key，**按照社区的话，if则不成立，放回的ids，即id的顺序则是按照KeyPostTimeZSet排序。**

```
func GetPostIDInOrder(p *models.ParamPostList) ([]string, error) {
   //从redis获取id
   key := getRedisKey(KeyPostTimeZSet)
   if p.Order == models.OrderScore {
      //根据用户请求中携带的order参数确定要查询的redis的key
      key = getRedisKey(KeyPostScoreZSet)
   }
   return getIDsFromKey(key, p.Page, p.Size)
}
```

其中返回调用了getIDsFromKey，利用redis中zset的特性将id数据按从大到小的规则返回

```
//3.ZREVRANGE 按分数从大到小查询指定数量的元素
return client.ZRevRange(key, start, end).Result()
```

#### mysql

**通过redis中按顺序拿到的post的id数据，**去mysql中查询帖子详情

```
posts, err := mysql.GetPostListByIDs(ids)
```

```
//GetPostListByIDs 根据给定的id列表查询数据
func GetPostListByIDs(ids []string) (postList []*models.Post, err error) {
   sqlStr := `select post_id,title,content,author_id,community_id,create_time 
   from post 
   where post_id in (?)
   order by FIND_IN_SET(post_id,?)`

   query, args, err := sqlx.In(sqlStr, ids, strings.Join(ids, ","))
   if err != nil {
      return nil, err
   }
   query = db.Rebind(query)

   err = db.Select(&postList, query, args...) //!!!!!
   if err != nil {
      return nil, err
   }
   return
}
```

根据posts中的数据查询作者和分区信息
