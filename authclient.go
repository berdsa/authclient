// Package authclient provides a client for interacting with the auth service
package authclient

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/gorilla/mux"
)

// Common errors returned by the client
var (
	ErrInvalidRequestBody = errors.New("invalid request body")
	ErrInvalidCredentials = errors.New("invalid credentials")
	ErrInvalidToken       = errors.New("invalid token")
	ErrInvalidUserData    = errors.New("invalid user data")
	ErrNetworkFailure     = errors.New("network failure")
	ErrServerError        = errors.New("server error")
)

// Client represents an auth service client
type Client struct {
	baseURL    string
	httpClient *http.Client
}

// NewClient creates a new auth service client
func NewClient(baseURL string, timeout time.Duration) *Client {
	return &Client{
		baseURL: baseURL,
		httpClient: &http.Client{
			Timeout: timeout,
		},
	}
}

// Response types

// AuthResponse is a common response structure returned by auth endpoints
type AuthResponse struct {
	Token        string `json:"token,omitempty"`
	RefreshToken string `json:"refresh_token,omitempty"`
	UserID       string `json:"user_id,omitempty"`
	Email        string `json:"email,omitempty"`
	Role         string `json:"role,omitempty"`
	ExpiresAt    int64  `json:"expires_at,omitempty"`
	Success      bool   `json:"success,omitempty"`
	Message      string `json:"message,omitempty"`
	Error        string `json:"error,omitempty"`
}

// UserClaims represents the claims extracted from a token
type UserClaims struct {
	UserID string `json:"user_id,omitempty"`
	Email  string `json:"email,omitempty"`
	Role   string `json:"role,omitempty"`
}

// contextKey is a custom type for context keys
type contextKey string

// Context keys
const (
	UserClaimsKey contextKey = "user_claims"
	TokenKey      contextKey = "token"
)

// Request types

// RegistrationRequest represents user registration data
type RegistrationRequest struct {
	Email    string `json:"email"`
	Password string `json:"password"`
	Role     string `json:"role"`
}

// LoginRequest represents login credentials
type LoginRequest struct {
	Email    string `json:"email"`
	Password string `json:"password"`
}

// RefreshRequest represents a token refresh request
type RefreshRequest struct {
	Token string `json:"token"`
}

// NewPasswordRequest represents password reset data
type NewPasswordRequest struct {
	Token       string `json:"token"`
	Password    string `json:"password"`
	NewPassword string `json:"new_password"`
}

// PermissionRequest represents a permission check request
type PermissionRequest struct {
	Email        string `json:"email"`
	RequiredRole string `json:"required_role"`
}

// Register registers a new user
func (c *Client) Register(email, password, role string) (*AuthResponse, error) {
	reqData := RegistrationRequest{
		Email:    email,
		Password: password,
		Role:     role,
	}

	reqBody, err := json.Marshal(reqData)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal registration request: %w", err)
	}

	resp, err := c.doRequest("POST", "/api/auth/register", reqBody)
	if err != nil {
		return nil, err
	}

	return resp, nil
}

// Login authenticates a user and returns auth tokens
func (c *Client) Login(email, password string) (*AuthResponse, error) {
	reqData := LoginRequest{
		Email:    email,
		Password: password,
	}

	reqBody, err := json.Marshal(reqData)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal login request: %w", err)
	}

	resp, err := c.doRequest("POST", "/api/auth/login", reqBody)
	if err != nil {
		return nil, err
	}

	return resp, nil
}

// RefreshToken refreshes an authentication token
func (c *Client) RefreshToken(token string) (*AuthResponse, error) {
	reqData := RefreshRequest{
		Token: token,
	}

	reqBody, err := json.Marshal(reqData)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal refresh request: %w", err)
	}

	resp, err := c.doRequest("POST", "/api/auth/refresh", reqBody)
	if err != nil {
		return nil, err
	}

	return resp, nil
}

// ValidateToken validates an authentication token
func (c *Client) ValidateToken(token string) (*AuthResponse, error) {
	reqData := RefreshRequest{
		Token: token,
	}

	reqBody, err := json.Marshal(reqData)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal validate request: %w", err)
	}

	resp, err := c.doRequest("POST", "/api/auth/validate", reqBody)
	if err != nil {
		return nil, err
	}

	return resp, nil
}

// ResetPassword resets a user's password
func (c *Client) ResetPassword(token, currentPassword, newPassword string) (*AuthResponse, error) {
	reqData := NewPasswordRequest{
		Token:       token,
		Password:    currentPassword,
		NewPassword: newPassword,
	}

	reqBody, err := json.Marshal(reqData)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal reset password request: %w", err)
	}

	resp, err := c.doRequest("POST", "/api/auth/reset-password", reqBody)
	if err != nil {
		return nil, err
	}

	return resp, nil
}

// CheckPermission checks if a user has the required permission
func (c *Client) CheckPermission(email, requiredRole string) (*AuthResponse, error) {
	reqData := PermissionRequest{
		Email:        email,
		RequiredRole: requiredRole,
	}

	reqBody, err := json.Marshal(reqData)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal permission request: %w", err)
	}

	resp, err := c.doRequest("POST", "/api/auth/check-permission", reqBody)
	if err != nil {
		return nil, err
	}

	return resp, nil
}

// doRequest performs an HTTP request to the auth service
func (c *Client) doRequest(method, endpoint string, body []byte) (*AuthResponse, error) {
	url := c.baseURL + endpoint
	req, err := http.NewRequest(method, url, bytes.NewBuffer(body))
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrNetworkFailure, err)
	}

	req.Header.Set("Content-Type", "application/json")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrNetworkFailure, err)
	}
	defer resp.Body.Close()

	var authResp AuthResponse
	if err := json.NewDecoder(resp.Body).Decode(&authResp); err != nil {
		return nil, fmt.Errorf("failed to decode response: %w", err)
	}

	// Handle error responses
	if resp.StatusCode >= 400 {
		switch resp.StatusCode {
		case http.StatusBadRequest:
			return nil, fmt.Errorf("%w: %s", ErrInvalidRequestBody, authResp.Error)
		case http.StatusUnauthorized:
			return nil, fmt.Errorf("%w: %s", ErrInvalidCredentials, authResp.Error)
		default:
			return nil, fmt.Errorf("%w: %s", ErrServerError, authResp.Error)
		}
	}

	return &authResp, nil
}

// Middleware functions

// ExtractTokenFromHeader extracts the bearer token from the Authorization header
func ExtractTokenFromHeader(r *http.Request) (string, error) {
	authHeader := r.Header.Get("Authorization")
	if authHeader == "" {
		return "", ErrInvalidToken
	}

	// Bearer token format: "Bearer <token>"
	splitToken := strings.Split(authHeader, "Bearer ")
	if len(splitToken) != 2 {
		return "", ErrInvalidToken
	}

	return strings.TrimSpace(splitToken[1]), nil
}

// AuthMiddleware creates middleware that validates the token and adds user claims to the request context
func (c *Client) AuthMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		token, err := ExtractTokenFromHeader(r)
		if err != nil {
			http.Error(w, "Unauthorized: "+err.Error(), http.StatusUnauthorized)
			return
		}

		// Validate token against auth service
		resp, err := c.ValidateToken(token)
		if err != nil {
			http.Error(w, "Unauthorized: "+err.Error(), http.StatusUnauthorized)
			return
		}

		// Create user claims and add to context
		claims := UserClaims{
			UserID: resp.UserID,
			Email:  resp.Email,
			Role:   resp.Role,
		}

		// Add both token and claims to context
		ctx := context.WithValue(r.Context(), TokenKey, token)
		ctx = context.WithValue(ctx, UserClaimsKey, claims)

		// Call the next handler with the updated context
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// RoleMiddleware creates middleware that restricts access based on user role
func (c *Client) RoleMiddleware(allowedRoles ...string) mux.MiddlewareFunc {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Get claims from context (set by AuthMiddleware)
			claims, ok := r.Context().Value(UserClaimsKey).(UserClaims)
			if !ok {
				http.Error(w, "Unauthorized: missing user claims", http.StatusUnauthorized)
				return
			}

			// Check if user's role is in the allowed roles
			roleAllowed := false
			for _, role := range allowedRoles {
				if claims.Role == role {
					roleAllowed = true
					break
				}
			}

			if !roleAllowed {
				http.Error(w, "Forbidden: insufficient permissions", http.StatusForbidden)
				return
			}

			// Call the next handler
			next.ServeHTTP(w, r)
		})
	}
}

// GetUserFromContext retrieves the user claims from the request context
func GetUserFromContext(ctx context.Context) (UserClaims, error) {
	claims, ok := ctx.Value(UserClaimsKey).(UserClaims)
	if !ok {
		return UserClaims{}, errors.New("user claims not found in context")
	}
	return claims, nil
}
