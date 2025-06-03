package controllers

import (
	"fmt"
	"log"
	"time"

	"github.com/gofiber/fiber/v2"
	"github.com/kooroshh/fiber-boostrap/app/models"
	"github.com/kooroshh/fiber-boostrap/app/repository"
	"github.com/kooroshh/fiber-boostrap/pkg/jwt_token"
	"github.com/kooroshh/fiber-boostrap/pkg/response"
	"go.elastic.co/apm"
	"golang.org/x/crypto/bcrypt"
)

func Register(ctx *fiber.Ctx) error {
	span, spanCtx := apm.StartSpan(ctx.Context(), "Register", "controller")
	defer span.End()

	user := new(models.User)
	err := ctx.BodyParser(user)
	if err != nil {
		errResp := fmt.Errorf("failed to parse request: %v", err)
		log.Println(errResp)
		return response.SendFailureResponse(ctx, fiber.StatusBadRequest, errResp.Error(), nil)
	}

	err = user.Validate()
	if err != nil {
		errResp := fmt.Errorf("failed to validate request: %v", err)
		log.Println(errResp)
		return response.SendFailureResponse(ctx, fiber.StatusBadRequest, errResp.Error(), nil)
	}

	hashPass, err := bcrypt.GenerateFromPassword([]byte(user.Password), bcrypt.DefaultCost)
	if err != nil {
		errResp := fmt.Errorf("failed to encrypt the password: %v", err)
		log.Println(errResp)
		return response.SendFailureResponse(ctx, fiber.StatusInternalServerError, errResp.Error(), nil)
	}

	user.Password = string(hashPass)

	err = repository.InsertNewUser(spanCtx, user)
	if err != nil {
		errResp := fmt.Errorf("failed to insert new user: %v", err)
		log.Println(errResp)
		return response.SendFailureResponse(ctx, fiber.StatusInternalServerError, errResp.Error(), nil)
	}

	res := user
	res.Password = ""

	return response.SendSuccessResponse(ctx, res)
}

func Login(ctx *fiber.Ctx) error {
	span, spanCtx := apm.StartSpan(ctx.Context(), "Login", "controller")
	defer span.End()

	// Parse request dan validasi request
	loginRequest := new(models.LoginRequest)
	resp := models.LoginResponse{}
	now := time.Now()

	err := ctx.BodyParser(loginRequest)
	if err != nil {
		errResp := fmt.Errorf("failed to parse request: %v", err)
		log.Println(errResp)
		return response.SendFailureResponse(ctx, fiber.StatusBadRequest, errResp.Error(), nil)
	}

	err = loginRequest.Validate()
	if err != nil {
		errResp := fmt.Errorf("failed to validate request: %v", err)
		log.Println(errResp)
		return response.SendFailureResponse(ctx, fiber.StatusBadRequest, errResp.Error(), nil)
	}

	user, err := repository.GetUserByUsername(spanCtx, loginRequest.Username)
	if err != nil {
		errResp := fmt.Errorf("failed to get username: %v", err)
		log.Println(errResp)
		return response.SendFailureResponse(ctx, fiber.StatusNotFound, "username atau password salah", nil)
	}

	err = bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(loginRequest.Password))
	if err != nil {
		errResp := fmt.Errorf("failed to check password: %v", err)
		log.Println(errResp)
		return response.SendFailureResponse(ctx, fiber.StatusNotFound, "username atau password salah", nil)
	}

	token, err := jwt_token.GenerateToken(spanCtx, user.Username, user.FullName, "token", now)
	if err != nil {
		errResp := fmt.Errorf("failed to generate token: %v", err)
		log.Println(errResp)
		return response.SendFailureResponse(ctx, fiber.StatusInternalServerError, "terjadi kesalahan pada sistem", nil)
	}

	refreshToken, err := jwt_token.GenerateToken(spanCtx, user.Username, user.FullName, "refresh_token", now)
	if err != nil {
		errResp := fmt.Errorf("failed to generate refresh token: %v", err)
		log.Println(errResp)
		return response.SendFailureResponse(ctx, fiber.StatusInternalServerError, "terjadi kesalahan pada sistem", nil)
	}

	userSession := &models.UserSession{
		UserID:              user.ID,
		Token:               token,
		RefreshToken:        refreshToken,
		TokenExpired:        now.Add(jwt_token.MapTypeToken["token"]),
		RefreshTokenExpired: now.Add(jwt_token.MapTypeToken["refresh_token"]),
	}

	err = repository.InsertNewUserSession(spanCtx, userSession)
	if err != nil {
		errResp := fmt.Errorf("failed insert user session: %v", err)
		log.Println(errResp)
		return response.SendFailureResponse(ctx, fiber.StatusInternalServerError, "terjadi kesalahan pada sistem", nil)
	}

	resp.Username = user.Username
	resp.FullName = user.FullName
	resp.Token = token
	resp.RefreshToken = refreshToken

	return response.SendSuccessResponse(ctx, resp)
}

func Logout(ctx *fiber.Ctx) error {
	span, spanCtx := apm.StartSpan(ctx.Context(), "Logout", "controller")
	defer span.End()

	token := ctx.Get("Authorization")
	err := repository.DeleteUserSessionByToken(spanCtx, token)
	if err != nil {
		errResp := fmt.Errorf("failed delete user session: %v", err)
		log.Println(errResp)
		return response.SendFailureResponse(ctx, fiber.StatusInternalServerError, "terjadi kesalahan pada sistem", nil)
	}
	return response.SendSuccessResponse(ctx, nil)
}

func RefreshToken(ctx *fiber.Ctx) error {
	span, spanCtx := apm.StartSpan(ctx.Context(), "RefreshToken", "controller")
	defer span.End()

	now := time.Now()
	refreshToken := ctx.Get("Authorization")
	username := ctx.Locals("username").(string)
	fullName := ctx.Locals("full_name").(string)

	token, err := jwt_token.GenerateToken(spanCtx, username, fullName, "token", now)
	if err != nil {
		errResp := fmt.Errorf("failed to generate token: %v", err)
		log.Println(errResp)
		return response.SendFailureResponse(ctx, fiber.StatusInternalServerError, "terjadi kesalahan pada sistem", nil)
	}

	err = repository.UpdateUserSessionToken(spanCtx, token, now.Add(jwt_token.MapTypeToken["token"]), refreshToken)
	if err != nil {
		errResp := fmt.Errorf("failed to update token: %v", err)
		log.Println(errResp)
		return response.SendFailureResponse(ctx, fiber.StatusInternalServerError, "terjadi kesalahan pada sistem", nil)
	}

	return response.SendSuccessResponse(ctx, fiber.Map{
		"token": token,
	})
}
