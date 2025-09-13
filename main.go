package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/gin-contrib/cors"
	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
	"github.com/redis/go-redis/v9"
	"github.com/spf13/viper"
	"gorm.io/driver/mysql"
	"gorm.io/gorm"
	"io"
	"log"
	"os"
	"strings"
	"time"
)

type UserJWT struct {
	UserID int
	jwt.RegisteredClaims
}

type UserForm struct {
	UserID   int    `gorm:"primaryKey;autoIncrement"`
	Username string `json:"username" binding:"required,numeric" gorm:"unique"`
	Name     string `json:"name" binding:"required"`
	Password string `json:"password" binding:"required,min=8,max=16"`
	UserType int    `json:"user_type" binding:"required,oneof=1 2"`
}

type PostForm struct {
	PostID  int       `json:"id" gorm:"primaryKey;autoIncrement"`
	Content string    `json:"content" binding:"required"`
	UserID  int       `json:"user_id" binding:"required"`
	Time    time.Time `json:"time" gorm:"autoCreateTime"`
	Likes   int       `json:"likes" gorm:"Default:0"`
}

type ReportForm struct {
	ReportID int    `gorm:"primaryKey;autoIncrement"`
	UserID   int    `json:"user_id" binding:"required"`
	PostID   int    `json:"post_id" binding:"required"`
	Content  string `json:"content"`
	Reason   string `json:"reason" binding:"required"`
	Status   int    `json:"status" gorm:"Default:0"`
}

type LoginForm struct {
	Username string `json:"username" binding:"required"`
	Password string `json:"password" binding:"required"`
}

type DeleteForm struct {
	PostID int `form:"post_id" binding:"required"`
	UserID int `form:"user_id" binding:"required"`
}

type EditForm struct {
	UserID  int    `json:"user_id" binding:"required"`
	PostID  int    `json:"post_id" binding:"required"`
	Content string `json:"content" binding:"required"`
}

type GetLikesForm struct {
	PostID int `form:"post_id" binding:"required"`
	UserID int `form:"user_id"`
}

type GetReportsForm struct {
	UserID int `form:"user_id"`
}

type GetReportsResForm struct {
	PostID  int    `json:"post_id"`
	Content string `json:"content"`
	Reason  string `json:"reason"`
	Status  int    `json:"status"`
}

type LikesForm struct {
	PostID int `json:"post_id" binding:"required" gorm:"primaryKey"`
	UserID int `json:"user_id" binding:"required" gorm:"primaryKey"`
}

type GetAllReportsForm struct {
	UserID int `form:"user_id" binding:"required"`
}

type GetAllReportsResForm struct {
	ReportID int    `json:"report_id"`
	Username string `json:"username"`
	PostID   int    `json:"post_id"`
	Content  string `json:"content"`
	Reason   string `json:"reason"`
}

type ProcessReportForm struct {
	UserID   int `json:"user_id" binding:"required"`
	ReportID int `json:"report_id" binding:"required"`
	Approval int `json:"approval" binding:"required,oneof=1 2"`
}

type ErrorResponse struct {
	StatusCode int    `json:"-"`
	Code       int    `json:"code"`
	Data       any    `json:"data"`
	Msg        string `json:"msg"`
}

func (e *ErrorResponse) Error() string {
	return e.Msg
}

func errorConverter(err error) *ErrorResponse {
	var se *json.SyntaxError
	var ute *json.UnmarshalTypeError

	switch {
	case errors.Is(err, io.EOF):
		return &ErrorResponse{StatusCode: 201, Code: 1001, Msg: "请求体不能为空", Data: nil}
	case errors.As(err, &se):
		return &ErrorResponse{StatusCode: 202, Code: 1002, Msg: "JSON 语法错误", Data: nil}
	case errors.Is(err, jwt.ErrTokenExpired):
		return &ErrorResponse{StatusCode: 203, Code: 1101, Msg: "token 已过期", Data: nil}
	case errors.Is(err, jwt.ErrTokenMalformed):
		return &ErrorResponse{StatusCode: 204, Code: 1103, Msg: "无效的 token", Data: nil}
	case errors.Is(err, jwt.ErrTokenUnverifiable):
		return &ErrorResponse{StatusCode: 205, Code: 1104, Msg: "token 验证失败", Data: nil}
	case errors.As(err, &ute):
		return &ErrorResponse{StatusCode: 206, Code: 1203, Msg: "字段类型不匹配", Data: nil}
	case errors.Is(err, gorm.ErrRecordNotFound):
		return &ErrorResponse{StatusCode: 207, Code: 1204, Msg: "资源不存在", Data: nil}
	case errors.Is(err, gorm.ErrDuplicatedKey):
		return &ErrorResponse{StatusCode: 208, Code: 1205, Msg: "重复数据", Data: nil}
	case errors.Is(err, redis.ErrClosed):
		return &ErrorResponse{StatusCode: 209, Code: 1301, Msg: "redis 连接已关闭", Data: nil}
	case errors.Is(err, redis.ErrPoolTimeout):
		return &ErrorResponse{StatusCode: 210, Code: 1303, Msg: "redis 连接超时", Data: nil}
	default:
		return &ErrorResponse{StatusCode: 211, Code: 1206, Msg: "未知错误", Data: nil}
	}
}

func errorHandler() gin.HandlerFunc {
	return func(c *gin.Context) {
		c.Next()
		if c.Errors.Last() != nil {
			err := c.Errors.Last().Err
			log.Printf("Error: %v | Path: %s | Method: %s\n", err, c.Request.URL.Path, c.Request.Method)
			err = errorConverter(err)
			e := err.(*ErrorResponse)
			c.JSON(e.StatusCode, e)
			return
		} else {
			log.Printf("Path: %s | Method: %s\n", c.Request.URL.Path, c.Request.Method)
		}
	}
}

func resHandler(code int, data any, msg string, c *gin.Context) {
	c.JSON(200, gin.H{
		"code": code,
		"data": data,
		"msg":  msg,
	})
}

const jwtKey = "aC4oF9wB7yC7xH7wA1hY2zC3lT9bA6dR"

func parseJwt(tokenstring string) (*UserJWT, error) {
	token, err := jwt.ParseWithClaims(tokenstring, &UserJWT{}, func(token *jwt.Token) (any, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, jwt.ErrTokenMalformed
		}
		return []byte(jwtKey), nil
	})
	if err != nil {
		return nil, err
	}

	if claims, ok := token.Claims.(*UserJWT); ok && token.Valid {
		return claims, nil
	} else {
		return nil, jwt.ErrTokenExpired
	}
}

func authorityVerify() gin.HandlerFunc {
	return func(c *gin.Context) {
		if c.Request.URL.Path == "/api/user/login" || c.Request.URL.Path == "/api/user/reg" {
			c.Next()
			return
		}
		aut := c.Request.Header.Get("Authorization")
		if !strings.HasPrefix(aut, "Bearer") || len(aut) <= 7 {
			c.Error(jwt.ErrTokenUnverifiable)
			return
		}
		token := aut[7:]
		claims, err := parseJwt(token)
		if err != nil {
			c.Error(err)
			return
		}
		c.Set("user_id", claims.UserID)
	}
}

func main() {
	// 读取配置文件
	viper.SetConfigFile("./config.yaml")
	if err := viper.ReadInConfig(); err != nil {
		log.Panicf("fail to read config file: %s", err.Error())
	}
	fmt.Println("success to read config file")

	// 配置日志文件
	logFile, err := os.OpenFile("./error.log", os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
	if err != nil {
		log.Panicf("fail to open log file: %s", err.Error())
	}
	log.SetOutput(logFile)

	// 连接数据库
	user := viper.GetString("database.user")
	password := viper.GetString("database.password")
	host := viper.GetString("database.host")
	port := viper.GetString("database.port")
	name := viper.GetString("database.name")

	dsn := fmt.Sprintf("%s:%s@tcp(%s:%s)/%s?charset=utf8mb4&parseTime=True&loc=Local", user, password, host, port, name)
	db, err := gorm.Open(mysql.Open(dsn), &gorm.Config{})
	if err != nil {
		log.Panicf("databese connection failed: %s", err.Error())
	}
	fmt.Println("success to connect database")

	db.AutoMigrate(&UserForm{}, &PostForm{}, &ReportForm{}, &LikesForm{})

	// 连接 redis
	user = viper.GetString("redis.user")
	host = viper.GetString("redis.host")
	port = viper.GetString("redis.port")
	password = viper.GetString("redis.password")
	name = viper.GetString("redis.name")

	opt, err := redis.ParseURL(fmt.Sprintf("redis://%s:%s@%s:%s/%s", user, password, host, port, name))
	if err != nil {
		log.Panicf("redis connection failed: %s", err.Error())
	}
	fmt.Println("success to connect redis")
	rdb := redis.NewClient(opt)
	ctx := context.Background()
	println(rdb)

	// 配置路由
	r := gin.Default()
	r.Use(errorHandler(), authorityVerify(), cors.Default())

	// 登录
	r.POST("/api/user/login", func(c *gin.Context) {
		var form LoginForm
		if err := c.ShouldBindJSON(&form); err != nil {
			c.Error(err)
			return
		}

		var user UserForm
		if err := db.Where("username = ? AND password = ?", form.Username, form.Password).First(&user).Error; err != nil {
			c.Error(err)
			return
		}

		// 生成 JWT
		claims := UserJWT{
			user.UserID,
			jwt.RegisteredClaims{
				ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Second)),
				IssuedAt:  jwt.NewNumericDate(time.Now()),
				NotBefore: jwt.NewNumericDate(time.Now()),
			},
		}
		jwtStr, err := jwt.NewWithClaims(jwt.SigningMethodHS256, claims).SignedString([]byte(jwtKey))
		if err != nil {
			c.Error(err)
			return
		}

		resHandler(200, gin.H{"user_id": user.UserID, "user_type": user.UserType, "token": jwtStr}, "success", c)
	})

	// 注册
	r.POST("/api/user/reg", func(c *gin.Context) {
		var form UserForm
		if err := c.ShouldBindJSON(&form); err != nil {
			c.Error(err)
			return
		}
		if err := db.Create(&form).Error; err != nil {
			c.Error(err)
			return
		}
		resHandler(200, nil, "success", c)
	})

	// 发布帖子
	r.POST("/api/student/post", func(c *gin.Context) {
		var form PostForm
		if err := c.ShouldBindJSON(&form); err != nil {
			c.Error(err)
			return
		}

		claims := c.GetInt("user_id")
		if claims != form.UserID {
			c.Error(jwt.ErrTokenUnverifiable)
			return
		}

		if err := db.Where("user_id = ?", form.UserID).First(&UserForm{}).Error; err != nil {
			c.Error(err)
			return
		}

		db.Create(&form)
		resHandler(200, nil, "success", c)
	})

	// 获取帖子
	r.GET("/api/student/post", func(c *gin.Context) {
		var posts []PostForm
		if err := db.Find(&posts).Error; err != nil {
			c.Error(err)
			return
		}
		resHandler(200, gin.H{"post_list": posts}, "success", c)
	})

	// 删除帖子
	r.DELETE("/api/student/post", func(c *gin.Context) {
		var form DeleteForm
		if err := c.ShouldBindQuery(&form); err != nil {
			c.Error(err)
			return
		}

		claims := c.GetInt("user_id")
		if claims != form.UserID {
			c.Error(jwt.ErrTokenUnverifiable)
			return
		}

		var post PostForm
		if err := db.Where("post_id = ? AND user_id = ?", form.PostID, form.UserID).First(&post).Error; err != nil {
			c.Error(err)
			return
		}

		db.Delete(&post)
		resHandler(200, nil, "success", c)
	})

	// 举报帖子
	r.POST("/api/student/report-post", func(c *gin.Context) {
		var form ReportForm
		if err := c.ShouldBindJSON(&form); err != nil {
			c.Error(err)
			return
		}

		claims := c.GetInt("user_id")
		if claims != form.UserID {
			c.Error(jwt.ErrTokenUnverifiable)
			return
		}

		var post PostForm
		if err := db.Where("post_id = ?", form.PostID).First(&post).Error; err != nil {
			c.Error(err)
			return
		}
		if err := db.Where("user_id = ?", form.UserID).First(&UserForm{}).Error; err != nil {
			c.Error(err)
			return
		}

		form.Content = post.Content
		db.Create(&form)
		resHandler(200, nil, "success", c)
	})

	//修改帖子
	r.PUT("/api/student/post", func(c *gin.Context) {
		var form EditForm
		if err := c.ShouldBindJSON(&form); err != nil {
			c.Error(err)
			return
		}

		claims := c.GetInt("user_id")
		if claims != form.UserID {
			c.Error(jwt.ErrTokenUnverifiable)
			return
		}

		var post PostForm
		if err := db.Where("post_id = ? AND user_id = ?", form.PostID, form.UserID).First(&post).Error; err != nil {
			c.Error(err)
			return
		}

		db.Model(&post).Update("content", form.Content)
		resHandler(200, nil, "success", c)
	})

	// 获取点赞数
	r.GET("/api/student/likes", func(c *gin.Context) {
		var form GetLikesForm
		if err := c.ShouldBindQuery(&form); err != nil {
			c.Error(err)
			return
		}

		likes, err := rdb.Get(ctx, fmt.Sprintf("post_%d", form.PostID)).Int()
		if err == redis.Nil {
			var post PostForm
			if err := db.Where("post_id = ?", form.PostID).First(&post).Error; err != nil {
				c.Error(err)
				return
			}
			likes = post.Likes
			if e := rdb.Set(ctx, fmt.Sprintf("post_%d", form.PostID), post.Likes, time.Hour).Err(); e != nil {
				c.Error(e)
				return
			}
		} else if err != nil {
			c.Error(err)
			return
		}
		resHandler(200, gin.H{"likes": likes}, "success", c)
	})

	// 查看举报审批
	r.GET("/api/student/report-post", func(c *gin.Context) {
		var form GetReportsForm
		if err := c.ShouldBindQuery(&form); err != nil {
			c.Error(err)
			return
		}

		var reports []ReportForm
		var results []GetReportsResForm
		if form.UserID == 0 {
			if err := db.Find(&reports).Error; err != nil {
				c.Error(err)
				return
			}
		} else {
			if err := db.Where("user_id = ?", form.UserID).Find(&reports).Error; err != nil {
				c.Error(err)
				return
			}
		}
		for _, report := range reports {
			var result GetReportsResForm
			result.PostID = report.PostID
			result.Reason = report.Reason
			result.Status = report.Status
			db.Model(&PostForm{}).Where("post_id = ?", report.PostID).Pluck("content", &result.Content)
			results = append(results, result)
		}
		resHandler(200, gin.H{"report_list": results}, "success", c)
	})

	// 点赞
	r.POST("/api/student/likes", func(c *gin.Context) {
		var form LikesForm
		if err := c.ShouldBindJSON(&form); err != nil {
			c.Error(err)
			return
		}

		claims := c.GetInt("user_id")
		if claims != form.UserID {
			c.Error(jwt.ErrTokenUnverifiable)
			return
		}
		if err := db.Where("user_id = ?", form.UserID).First(&UserForm{}).Error; err != nil {
			c.Error(err)
			return
		}
		if err := db.Where("post_id = ?", form.PostID).First(&PostForm{}).Error; err != nil {
			c.Error(err)
			return
		}

		var likes LikesForm
		if err := db.Where("post_id = ? AND user_id = ?", form.PostID, form.UserID).First(&likes).Error; err != nil {
			if !errors.Is(err, gorm.ErrRecordNotFound) {
				c.Error(err)
				return
			}
			db.Create(&form)
			db.Where("post_id = ?", form.PostID).First(&PostForm{}).Update("likes", gorm.Expr("likes + ?", 1))
		} else {
			db.Delete(&likes)
			db.Where("post_id = ?", form.PostID).First(&PostForm{}).Update("likes", gorm.Expr("likes - ?", 1))
		}

		var likesCount int
		db.Model(&PostForm{}).Where("post_id = ?", form.PostID).Pluck("likes", &likesCount)
		if err := rdb.Set(ctx, fmt.Sprintf("post_%d", form.PostID), likesCount, time.Hour).Err(); err != nil {
			c.Error(err)
			return
		}

		resHandler(200, nil, "success", c)
	})

	// 管理员获取被举报帖子
	r.GET("/api/admin/report", func(c *gin.Context) {
		var form GetAllReportsForm
		if err := c.ShouldBindQuery(&form); err != nil {
			c.Error(err)
			return
		}

		claims := c.GetInt("user_id")
		if claims != form.UserID {
			c.Error(jwt.ErrTokenUnverifiable)
			return
		}

		if err := db.Where("user_id = ? AND user_type = ?", form.UserID, 2).First(&UserForm{}).Error; err != nil {
			c.Error(err)
			return
		}

		var reports []ReportForm
		if err := db.Where(map[string]any{"Status": 0}).Find(&reports).Error; err != nil {
			c.Error(err)
			return
		}

		var results []GetAllReportsResForm
		for _, report := range reports {
			var result GetAllReportsResForm
			result.ReportID = report.ReportID
			result.PostID = report.PostID
			result.Reason = report.Reason
			db.Model(&UserForm{}).Where("user_id = ?", report.UserID).Pluck("username", &result.Username)
			db.Model(&PostForm{}).Where("post_id = ?", report.PostID).Pluck("content", &result.Content)
			results = append(results, result)
		}

		resHandler(200, gin.H{"report_list": results}, "success", c)
	})

	// 审核被举报的帖子
	r.POST("/api/admin/report", func(c *gin.Context) {
		var form ProcessReportForm
		if err := c.ShouldBindJSON(&form); err != nil {
			c.Error(err)
			return
		}

		claims := c.GetInt("user_id")
		if claims != form.UserID {
			c.Error(jwt.ErrTokenUnverifiable)
			return
		}

		if err := db.Where("user_id = ? AND user_type = ?", form.UserID, 2).First(&UserForm{}).Error; err != nil {
			c.Error(err)
			return
		}

		var report ReportForm
		db.Where("report_id = ?", form.ReportID).First(&report)
		db.Model(&report).Update("status", form.Approval)

		if form.Approval == 1 {
			var postID int
			var post PostForm
			db.Model(ReportForm{}).Where("report_id = ?", form.ReportID).Pluck("post_id", &postID)
			db.Where("post_id = ?", postID).First(&post)
			db.Delete(&post)
		}

		resHandler(200, nil, "success", c)
	})

	// 启动服务器
	host = viper.GetString("server.host")
	port = viper.GetString("server.port")

	if err = r.Run(host + ":" + port); err != nil {
		log.Panicf("http server failed: %s", err.Error())
	}
}
