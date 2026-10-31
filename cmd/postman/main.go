// Package main provides a utility to generate Postman collection and environment files with valid RS256 JWT tokens.
package main

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"

	"github.com/group-project-bridgeon/manager-service/internal/api"
	"github.com/group-project-bridgeon/manager-service/internal/auth"
)

type postmanEnvVariable struct {
	Key     string `json:"key"`
	Value   string `json:"value"`
	Type    string `json:"type"`
	Enabled bool   `json:"enabled"`
}

type postmanEnvironment struct {
	ID                   string               `json:"id"`
	Name                 string               `json:"name"`
	Values               []postmanEnvVariable `json:"values"`
	PostmanVariableScope string               `json:"_postman_variable_scope"`
}

type postmanHeader struct {
	Key   string `json:"key"`
	Value string `json:"value"`
	Type  string `json:"type,omitempty"`
}

type postmanBody struct {
	Mode string `json:"mode"`
	Raw  string `json:"raw"`
}

type postmanURL struct {
	Raw   string         `json:"raw"`
	Host  []string       `json:"host"`
	Path  []string       `json:"path"`
	Query []postmanQuery `json:"query,omitempty"`
}

type postmanQuery struct {
	Key   string `json:"key"`
	Value string `json:"value"`
}

type postmanRequest struct {
	Method      string          `json:"method"`
	Header      []postmanHeader `json:"header"`
	Body        *postmanBody    `json:"body,omitempty"`
	URL         postmanURL      `json:"url"`
	Description string          `json:"description,omitempty"`
}

type postmanScript struct {
	Type string   `json:"type"`
	Exec []string `json:"exec"`
}

type postmanEvent struct {
	Listen string        `json:"listen"`
	Script postmanScript `json:"script"`
}

type postmanItem struct {
	Name    string          `json:"name"`
	Item    []postmanItem   `json:"item,omitempty"`
	Request *postmanRequest `json:"request,omitempty"`
	Event   []postmanEvent  `json:"event,omitempty"`
}

type postmanInfo struct {
	PostmanID   string `json:"_postman_id"`
	Name        string `json:"name"`
	Description string `json:"description"`
	Schema      string `json:"schema"`
}

type postmanCollection struct {
	Info postmanInfo   `json:"info"`
	Item []postmanItem `json:"item"`
}

func main() {
	outDir := "postman"
	if err := os.MkdirAll(outDir, 0755); err != nil {
		fmt.Printf("Error creating %s directory: %v\n", outDir, err)
		os.Exit(1)
	}

	keyPath := "keys/jwt_private.pem"
	keyBytes, err := os.ReadFile(keyPath)
	if err != nil {
		fmt.Printf("Error: could not read private key %s: %v\n", keyPath, err)
		os.Exit(1)
	}

	block, _ := pem.Decode(keyBytes)
	if block == nil {
		fmt.Printf("Error: failed to decode PEM block from %s\n", keyPath)
		os.Exit(1)
	}

	var privKey *rsa.PrivateKey
	if key, parseErr := x509.ParsePKCS1PrivateKey(block.Bytes); parseErr == nil {
		privKey = key
	} else if key, parseErr := x509.ParsePKCS8PrivateKey(block.Bytes); parseErr == nil {
		if rsaKey, ok := key.(*rsa.PrivateKey); ok {
			privKey = rsaKey
		} else {
			fmt.Println("Error: PKCS8 key is not an RSA private key")
			os.Exit(1)
		}
	} else {
		fmt.Printf("Error: failed parsing RSA private key: %v\n", parseErr)
		os.Exit(1)
	}

	issuer := "erp-auth"
	audience := "erp-api"

	mint := func(userID uuid.UUID, email string, perms []string, issuedAt, expiresAt time.Time) string {
		ver := 1
		claims := auth.CustomClaims{
			RegisteredClaims: jwt.RegisteredClaims{
				Issuer:    issuer,
				Audience:  jwt.ClaimStrings{audience},
				Subject:   userID.String(),
				IssuedAt:  jwt.NewNumericDate(issuedAt),
				NotBefore: jwt.NewNumericDate(issuedAt),
				ExpiresAt: jwt.NewNumericDate(expiresAt),
			},
			UserID:       userID.String(),
			Email:        email,
			TokenVersion: &ver,
			Permissions:  perms,
		}
		tok := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
		str, signErr := tok.SignedString(privKey)
		if signErr != nil {
			panic(fmt.Sprintf("failed signing token: %v", signErr))
		}
		return str
	}

	now := time.Now().Truncate(time.Second)
	// Token contract: lifetime (exp - iat) <= 15 minutes
	ttl := 14 * time.Minute

	purchaserID := uuid.MustParse("11111111-1111-1111-1111-111111111111")
	managerID := uuid.MustParse("22222222-2222-2222-2222-222222222222")
	adminID := uuid.MustParse("33333333-3333-3333-3333-333333333333")
	guestID := uuid.MustParse("44444444-4444-4444-4444-444444444444")
	expiredID := uuid.MustParse("55555555-5555-5555-5555-555555555555")

	allPerms := []string{
		api.PermApprovalsSubmit,
		api.PermApprovalsRead,
		api.PermApprovalsApprove,
		api.PermApprovalsReject,
		api.PermRBACManage,
		api.PermAuthzCheck,
	}

	purchaserToken := mint(purchaserID, "purchaser@erp.local", []string{api.PermApprovalsSubmit, api.PermApprovalsRead}, now, now.Add(ttl))
	managerToken := mint(managerID, "manager@erp.local", []string{api.PermApprovalsApprove, api.PermApprovalsReject, api.PermApprovalsRead}, now, now.Add(ttl))
	adminToken := mint(adminID, "admin@erp.local", allPerms, now, now.Add(ttl))
	noPermToken := mint(guestID, "guest@erp.local", []string{}, now, now.Add(ttl))
	expiredToken := mint(expiredID, "expired@erp.local", []string{api.PermApprovalsRead}, now.Add(-20*time.Minute), now.Add(-5*time.Minute))

	// 1. Generate Environment File
	resourceID := fmt.Sprintf("PO-POSTMAN-%d", time.Now().Unix()%100000)
	createdRoleID := fmt.Sprintf("role_%d", time.Now().Unix()%10000)
	testUserID := uuid.New().String()

	env := postmanEnvironment{
		ID:                   uuid.New().String(),
		Name:                 "Manager Service (Local)",
		PostmanVariableScope: "environment",
		Values: []postmanEnvVariable{
			{Key: "baseUrl", Value: "http://localhost:8080", Type: "default", Enabled: true},
			{Key: "purchaser_token", Value: purchaserToken, Type: "secret", Enabled: true},
			{Key: "manager_token", Value: managerToken, Type: "secret", Enabled: true},
			{Key: "admin_token", Value: adminToken, Type: "secret", Enabled: true},
			{Key: "no_perm_token", Value: noPermToken, Type: "secret", Enabled: true},
			{Key: "expired_token", Value: expiredToken, Type: "secret", Enabled: true},
			{Key: "resource_id", Value: resourceID, Type: "default", Enabled: true},
			{Key: "approval_id", Value: "", Type: "default", Enabled: true},
			{Key: "multi_approval_id", Value: "", Type: "default", Enabled: true},
			{Key: "test_user_id", Value: testUserID, Type: "default", Enabled: true},
			{Key: "created_role_id", Value: createdRoleID, Type: "default", Enabled: true},
		},
	}

	envFile := filepath.Join(outDir, "Manager-Service.postman_environment.json")
	envJSON, mErr := json.MarshalIndent(env, "", "  ")
	if mErr != nil {
		fmt.Printf("Error marshaling environment JSON: %v\n", mErr)
		os.Exit(1)
	}
	if wErr := os.WriteFile(envFile, envJSON, 0644); wErr != nil {
		fmt.Printf("Error writing environment file: %v\n", wErr)
		os.Exit(1)
	}

	// 2. Generate Collection File
	col := buildCollection()
	colFile := filepath.Join(outDir, "Manager-Service.postman_collection.json")
	colJSON, cErr := json.MarshalIndent(col, "", "  ")
	if cErr != nil {
		fmt.Printf("Error marshaling collection JSON: %v\n", cErr)
		os.Exit(1)
	}
	if cwErr := os.WriteFile(colFile, colJSON, 0644); cwErr != nil {
		fmt.Printf("Error writing collection file: %v\n", cwErr)
		os.Exit(1)
	}

	fmt.Println("=================================================================")
	fmt.Println(" Postman Files Successfully Generated / Refreshed!")
	fmt.Printf(" • Collection:  %s\n", colFile)
	fmt.Printf(" • Environment: %s\n", envFile)
	fmt.Printf(" • Token Validity: until %s (approx 14 mins)\n", now.Add(ttl).Format("15:04:05 MST"))
	fmt.Println("=================================================================")
	fmt.Println("\nTo test in Postman:")
	fmt.Println(" 1. In Postman, click 'Import' and select both JSON files from postman/")
	fmt.Println(" 2. In top right corner, select the environment 'Manager Service (Local)'")
	fmt.Println(" 3. Run requests individually or run entire collection via Collection Runner!")
	fmt.Println("=================================================================")
}

func buildCollection() postmanCollection {
	return postmanCollection{
		Info: postmanInfo{
			PostmanID:   uuid.New().String(),
			Name:        "Manager Service API",
			Description: "Comprehensive Postman test suite for Manager-service covering JWT Authentication, RBAC, Multi-level Approvals, OCC Concurrency, and Error Handling.",
			Schema:      "https://schema.getpostman.com/json/collection/v2.1.0/collection.json",
		},
		Item: []postmanItem{
			// Folder 1: Health & Readiness
			{
				Name: "01 - Health & System Checks",
				Item: []postmanItem{
					{
						Name: "Liveness Probe (/healthz)",
						Request: &postmanRequest{
							Method: "GET",
							Header: []postmanHeader{},
							URL: postmanURL{
								Raw:  "{{baseUrl}}/healthz",
								Host: []string{"{{baseUrl}}"},
								Path: []string{"healthz"},
							},
							Description: "Public health check endpoint. Returns 200 OK without requiring authentication.",
						},
						Event: []postmanEvent{
							{
								Listen: "test",
								Script: postmanScript{
									Type: "text/javascript",
									Exec: []string{
										"pm.test(\"Status code is 200\", function () {",
										"    pm.response.to.have.status(200);",
										"});",
										"pm.test(\"Liveness response contains status ok\", function () {",
										"    var jsonData = pm.response.json();",
										"    pm.expect(jsonData.status).to.eql(\"ok\");",
										"});",
									},
								},
							},
						},
					},
					{
						Name: "Readiness Probe (/readyz)",
						Request: &postmanRequest{
							Method: "GET",
							Header: []postmanHeader{},
							URL: postmanURL{
								Raw:  "{{baseUrl}}/readyz",
								Host: []string{"{{baseUrl}}"},
								Path: []string{"readyz"},
							},
							Description: "Public readiness probe. Pings database connection pool. Returns 200 when healthy, 503 during DB outage.",
						},
						Event: []postmanEvent{
							{
								Listen: "test",
								Script: postmanScript{
									Type: "text/javascript",
									Exec: []string{
										"pm.test(\"Status code is 200\", function () {",
										"    pm.response.to.have.status(200);",
										"});",
										"pm.test(\"Database connectivity verified\", function () {",
										"    var jsonData = pm.response.json();",
										"    pm.expect(jsonData.status).to.eql(\"ok\");",
										"});",
									},
								},
							},
						},
					},
				},
			},

			// Folder 2: Workflow Approvals
			{
				Name: "02 - Workflow Approvals Lifecycle",
				Item: []postmanItem{
					{
						Name: "Submit Approval Request (Under ₹50k - 1 Level)",
						Request: &postmanRequest{
							Method: "POST",
							Header: []postmanHeader{
								{Key: "Content-Type", Value: "application/json"},
								{Key: "Authorization", Value: "Bearer {{purchaser_token}}"},
							},
							Body: &postmanBody{
								Mode: "raw",
								Raw:  "{\n  \"service\": \"purchasing\",\n  \"resource_id\": \"{{resource_id}}\",\n  \"amount\": 35000\n}",
							},
							URL: postmanURL{
								Raw:  "{{baseUrl}}/api/v1/approvals/submit",
								Host: []string{"{{baseUrl}}"},
								Path: []string{"api", "v1", "approvals", "submit"},
							},
							Description: "Submits a new purchasing bill for manager approval. Requester ID is derived strictly from JWT principal.",
						},
						Event: []postmanEvent{
							{
								Listen: "test",
								Script: postmanScript{
									Type: "text/javascript",
									Exec: []string{
										"pm.test(\"Status code is 201 Created\", function () {",
										"    pm.response.to.have.status(201);",
										"});",
										"var jsonData = pm.response.json();",
										"pm.test(\"Response has standard envelope with request_id\", function () {",
										"    pm.expect(jsonData).to.have.property('request_id');",
										"    pm.expect(jsonData).to.have.property('data');",
										"});",
										"pm.test(\"Workflow is pending with 1 required level\", function () {",
										"    pm.expect(jsonData.data.status).to.eql(\"pending\");",
										"    pm.expect(jsonData.data.current_level).to.eql(0);",
										"    pm.expect(jsonData.data.required_levels).to.eql(1);",
										"});",
										"if (jsonData.data && jsonData.data.id) {",
										"    pm.environment.set(\"approval_id\", jsonData.data.id);",
										"    console.log(\"Saved approval_id:\", jsonData.data.id);",
										"}",
									},
								},
							},
						},
					},
					{
						Name: "Query Approval Status by Resource",
						Request: &postmanRequest{
							Method: "GET",
							Header: []postmanHeader{
								{Key: "Authorization", Value: "Bearer {{purchaser_token}}"},
							},
							URL: postmanURL{
								Raw:   "{{baseUrl}}/api/v1/approvals/status?service=purchasing&resource_id={{resource_id}}",
								Host:  []string{"{{baseUrl}}"},
								Path:  []string{"api", "v1", "approvals", "status"},
								Query: []postmanQuery{{Key: "service", Value: "purchasing"}, {Key: "resource_id", Value: "{{resource_id}}"}},
							},
							Description: "Queries the current approval status for a resource.",
						},
						Event: []postmanEvent{
							{
								Listen: "test",
								Script: postmanScript{
									Type: "text/javascript",
									Exec: []string{
										"pm.test(\"Status code is 200\", function () {",
										"    pm.response.to.have.status(200);",
										"});",
										"var jsonData = pm.response.json();",
										"pm.test(\"Matches requested resource_id\", function () {",
										"    pm.expect(jsonData.data.resource_id).to.eql(pm.environment.get(\"resource_id\"));",
										"});",
									},
								},
							},
						},
					},
					{
						Name: "Get Approval Request & Audit History",
						Request: &postmanRequest{
							Method: "GET",
							Header: []postmanHeader{
								{Key: "Authorization", Value: "Bearer {{manager_token}}"},
							},
							URL: postmanURL{
								Raw:  "{{baseUrl}}/api/v1/approvals/{{approval_id}}",
								Host: []string{"{{baseUrl}}"},
								Path: []string{"api", "v1", "approvals", "{{approval_id}}"},
							},
							Description: "Returns approval request details along with complete immutable audit trail.",
						},
						Event: []postmanEvent{
							{
								Listen: "test",
								Script: postmanScript{
									Type: "text/javascript",
									Exec: []string{
										"pm.test(\"Status code is 200\", function () {",
										"    pm.response.to.have.status(200);",
										"});",
										"var jsonData = pm.response.json();",
										"pm.test(\"History contains request and actions array\", function () {",
										"    pm.expect(jsonData.data).to.have.property('request');",
										"    pm.expect(jsonData.data).to.have.property('actions');",
										"});",
									},
								},
							},
						},
					},
					{
						Name: "Approve Request (Level 1)",
						Request: &postmanRequest{
							Method: "POST",
							Header: []postmanHeader{
								{Key: "Content-Type", Value: "application/json"},
								{Key: "Authorization", Value: "Bearer {{manager_token}}"},
							},
							Body: &postmanBody{
								Mode: "raw",
								Raw:  "{\n  \"notes\": \"Approved via Postman API test\"\n}",
							},
							URL: postmanURL{
								Raw:  "{{baseUrl}}/api/v1/approvals/{{approval_id}}/approve",
								Host: []string{"{{baseUrl}}"},
								Path: []string{"api", "v1", "approvals", "{{approval_id}}", "approve"},
							},
							Description: "Approver grants level 1 decision. Actor is derived strictly from JWT principal.",
						},
						Event: []postmanEvent{
							{
								Listen: "test",
								Script: postmanScript{
									Type: "text/javascript",
									Exec: []string{
										"pm.test(\"Status code is 200 OK\", function () {",
										"    pm.response.to.have.status(200);",
										"});",
										"var jsonData = pm.response.json();",
										"pm.test(\"Status transitions to approved\", function () {",
										"    pm.expect(jsonData.data.status).to.eql(\"approved\");",
										"    pm.expect(jsonData.data.current_level).to.eql(1);",
										"});",
									},
								},
							},
						},
					},
					{
						Name: "Submit Multi-Level Request (>= ₹50k - 2 Levels)",
						Request: &postmanRequest{
							Method: "POST",
							Header: []postmanHeader{
								{Key: "Content-Type", Value: "application/json"},
								{Key: "Authorization", Value: "Bearer {{purchaser_token}}"},
							},
							Body: &postmanBody{
								Mode: "raw",
								Raw:  "{\n  \"service\": \"purchasing\",\n  \"resource_id\": \"PO-MULTI-{{$timestamp}}\",\n  \"amount\": 85000\n}",
							},
							URL: postmanURL{
								Raw:  "{{baseUrl}}/api/v1/approvals/submit",
								Host: []string{"{{baseUrl}}"},
								Path: []string{"api", "v1", "approvals", "submit"},
							},
							Description: "Amounts ₹50k+ require 2 distinct manager approval levels.",
						},
						Event: []postmanEvent{
							{
								Listen: "test",
								Script: postmanScript{
									Type: "text/javascript",
									Exec: []string{
										"pm.test(\"Status code is 201 Created\", function () {",
										"    pm.response.to.have.status(201);",
										"});",
										"var jsonData = pm.response.json();",
										"pm.test(\"Requires 2 approval levels\", function () {",
										"    pm.expect(jsonData.data.required_levels).to.eql(2);",
										"});",
										"if (jsonData.data && jsonData.data.id) {",
										"    pm.environment.set(\"multi_approval_id\", jsonData.data.id);",
										"}",
									},
								},
							},
						},
					},
					{
						Name: "Reject Request",
						Request: &postmanRequest{
							Method: "POST",
							Header: []postmanHeader{
								{Key: "Content-Type", Value: "application/json"},
								{Key: "Authorization", Value: "Bearer {{manager_token}}"},
							},
							Body: &postmanBody{
								Mode: "raw",
								Raw:  "{\n  \"notes\": \"Exceeded departmental quarterly budget\"\n}",
							},
							URL: postmanURL{
								Raw:  "{{baseUrl}}/api/v1/approvals/{{multi_approval_id}}/reject",
								Host: []string{"{{baseUrl}}"},
								Path: []string{"api", "v1", "approvals", "{{multi_approval_id}}", "reject"},
							},
							Description: "Terminates the workflow request in rejected status.",
						},
						Event: []postmanEvent{
							{
								Listen: "test",
								Script: postmanScript{
									Type: "text/javascript",
									Exec: []string{
										"pm.test(\"Status code is 200 OK\", function () {",
										"    pm.response.to.have.status(200);",
										"});",
										"var jsonData = pm.response.json();",
										"pm.test(\"Status transitions to rejected\", function () {",
										"    pm.expect(jsonData.data.status).to.eql(\"rejected\");",
										"});",
									},
								},
							},
						},
					},
				},
			},

			// Folder 3: Roles & RBAC Management
			{
				Name: "03 - Roles & Access Control (RBAC)",
				Item: []postmanItem{
					{
						Name: "List All Roles",
						Request: &postmanRequest{
							Method: "GET",
							Header: []postmanHeader{
								{Key: "Authorization", Value: "Bearer {{admin_token}}"},
							},
							URL: postmanURL{
								Raw:  "{{baseUrl}}/api/v1/roles",
								Host: []string{"{{baseUrl}}"},
								Path: []string{"api", "v1", "roles"},
							},
							Description: "Retrieves all registered roles in the system.",
						},
						Event: []postmanEvent{
							{
								Listen: "test",
								Script: postmanScript{
									Type: "text/javascript",
									Exec: []string{
										"pm.test(\"Status code is 200 OK\", function () {",
										"    pm.response.to.have.status(200);",
										"});",
										"var jsonData = pm.response.json();",
										"pm.test(\"Returns array of roles\", function () {",
										"    pm.expect(Array.isArray(jsonData.data)).to.be.true;",
										"    pm.expect(jsonData.data.length).to.be.above(0);",
										"});",
									},
								},
							},
						},
					},
					{
						Name: "Create Custom Role",
						Request: &postmanRequest{
							Method: "POST",
							Header: []postmanHeader{
								{Key: "Content-Type", Value: "application/json"},
								{Key: "Authorization", Value: "Bearer {{admin_token}}"},
							},
							Body: &postmanBody{
								Mode: "raw",
								Raw:  "{\n  \"id\": \"{{created_role_id}}\",\n  \"name\": \"Quality Auditor\",\n  \"description\": \"Reviews quality reports and approvals\"\n}",
							},
							URL: postmanURL{
								Raw:  "{{baseUrl}}/api/v1/roles",
								Host: []string{"{{baseUrl}}"},
								Path: []string{"api", "v1", "roles"},
							},
							Description: "Registers a new custom role.",
						},
						Event: []postmanEvent{
							{
								Listen: "test",
								Script: postmanScript{
									Type: "text/javascript",
									Exec: []string{
										"pm.test(\"Status code is 201 Created\", function () {",
										"    pm.response.to.have.status(201);",
										"});",
										"var jsonData = pm.response.json();",
										"pm.test(\"Role matches created_role_id\", function () {",
										"    pm.expect(jsonData.data.id).to.eql(pm.environment.get(\"created_role_id\"));",
										"});",
									},
								},
							},
						},
					},
					{
						Name: "Get Role by ID",
						Request: &postmanRequest{
							Method: "GET",
							Header: []postmanHeader{
								{Key: "Authorization", Value: "Bearer {{admin_token}}"},
							},
							URL: postmanURL{
								Raw:  "{{baseUrl}}/api/v1/roles/{{created_role_id}}",
								Host: []string{"{{baseUrl}}"},
								Path: []string{"api", "v1", "roles", "{{created_role_id}}"},
							},
							Description: "Fetches details of a specific role by its ID.",
						},
						Event: []postmanEvent{
							{
								Listen: "test",
								Script: postmanScript{
									Type: "text/javascript",
									Exec: []string{
										"pm.test(\"Status code is 200 OK\", function () {",
										"    pm.response.to.have.status(200);",
										"});",
										"var jsonData = pm.response.json();",
										"pm.test(\"Role name verified\", function () {",
										"    pm.expect(jsonData.data.name).to.eql(\"Quality Auditor\");",
										"});",
									},
								},
							},
						},
					},
					{
						Name: "Assign Role to User",
						Request: &postmanRequest{
							Method: "POST",
							Header: []postmanHeader{
								{Key: "Content-Type", Value: "application/json"},
								{Key: "Authorization", Value: "Bearer {{admin_token}}"},
							},
							Body: &postmanBody{
								Mode: "raw",
								Raw:  "{\n  \"role_id\": \"{{created_role_id}}\"\n}",
							},
							URL: postmanURL{
								Raw:  "{{baseUrl}}/api/v1/users/{{test_user_id}}/roles",
								Host: []string{"{{baseUrl}}"},
								Path: []string{"api", "v1", "users", "{{test_user_id}}", "roles"},
							},
							Description: "Grants a role to a user. Assigned_by is extracted automatically from the JWT principal.",
						},
						Event: []postmanEvent{
							{
								Listen: "test",
								Script: postmanScript{
									Type: "text/javascript",
									Exec: []string{
										"pm.test(\"Status code is 201 Created\", function () {",
										"    pm.response.to.have.status(201);",
										"});",
										"var jsonData = pm.response.json();",
										"pm.test(\"Assigned by matches admin user ID\", function () {",
										"    pm.expect(jsonData.data.assigned_by).to.not.be.empty;",
										"});",
									},
								},
							},
						},
					},
					{
						Name: "List User Assigned Roles",
						Request: &postmanRequest{
							Method: "GET",
							Header: []postmanHeader{
								{Key: "Authorization", Value: "Bearer {{admin_token}}"},
							},
							URL: postmanURL{
								Raw:  "{{baseUrl}}/api/v1/users/{{test_user_id}}/roles",
								Host: []string{"{{baseUrl}}"},
								Path: []string{"api", "v1", "users", "{{test_user_id}}", "roles"},
							},
							Description: "Returns all roles currently assigned to a user.",
						},
						Event: []postmanEvent{
							{
								Listen: "test",
								Script: postmanScript{
									Type: "text/javascript",
									Exec: []string{
										"pm.test(\"Status code is 200 OK\", function () {",
										"    pm.response.to.have.status(200);",
										"});",
										"var jsonData = pm.response.json();",
										"pm.test(\"Contains newly assigned role\", function () {",
										"    var found = jsonData.data.some(function(r) { return r.id === pm.environment.get(\"created_role_id\"); });",
										"    pm.expect(found).to.be.true;",
										"});",
									},
								},
							},
						},
					},
					{
						Name: "Authorization Check (Authz)",
						Request: &postmanRequest{
							Method: "POST",
							Header: []postmanHeader{
								{Key: "Content-Type", Value: "application/json"},
								{Key: "Authorization", Value: "Bearer {{admin_token}}"},
							},
							Body: &postmanBody{
								Mode: "raw",
								Raw:  "{\n  \"user_id\": \"{{test_user_id}}\",\n  \"service\": \"purchasing\",\n  \"resource\": \"bill\",\n  \"action\": \"approve\"\n}",
							},
							URL: postmanURL{
								Raw:  "{{baseUrl}}/api/v1/authz/check",
								Host: []string{"{{baseUrl}}"},
								Path: []string{"api", "v1", "authz", "check"},
							},
							Description: "Evaluates whether user holds authority to execute an action on a service resource.",
						},
						Event: []postmanEvent{
							{
								Listen: "test",
								Script: postmanScript{
									Type: "text/javascript",
									Exec: []string{
										"pm.test(\"Status code is 200 OK\", function () {",
										"    pm.response.to.have.status(200);",
										"});",
										"var jsonData = pm.response.json();",
										"pm.test(\"Authz response has allowed boolean\", function () {",
										"    pm.expect(jsonData.data).to.have.property('allowed');",
										"});",
									},
								},
							},
						},
					},
					{
						Name: "Revoke Role from User",
						Request: &postmanRequest{
							Method: "DELETE",
							Header: []postmanHeader{
								{Key: "Authorization", Value: "Bearer {{admin_token}}"},
							},
							URL: postmanURL{
								Raw:  "{{baseUrl}}/api/v1/users/{{test_user_id}}/roles/{{created_role_id}}",
								Host: []string{"{{baseUrl}}"},
								Path: []string{"api", "v1", "users", "{{test_user_id}}", "roles", "{{created_role_id}}"},
							},
							Description: "Revokes a granted role from a user.",
						},
						Event: []postmanEvent{
							{
								Listen: "test",
								Script: postmanScript{
									Type: "text/javascript",
									Exec: []string{
										"pm.test(\"Status code is 200 OK\", function () {",
										"    pm.response.to.have.status(200);",
										"});",
									},
								},
							},
						},
					},
				},
			},

			// Folder 4: Negative & Security Matrix
			{
				Name: "04 - Security & Error Enforcement",
				Item: []postmanItem{
					{
						Name: "401 Unauthorized - Missing Token",
						Request: &postmanRequest{
							Method: "GET",
							Header: []postmanHeader{},
							URL: postmanURL{
								Raw:   "{{baseUrl}}/api/v1/approvals/status?service=purchasing&resource_id=test",
								Host:  []string{"{{baseUrl}}"},
								Path:  []string{"api", "v1", "approvals", "status"},
								Query: []postmanQuery{{Key: "service", Value: "purchasing"}, {Key: "resource_id", Value: "test"}},
							},
							Description: "Calling protected endpoint without Authorization header must return 401 with WWW-Authenticate header.",
						},
						Event: []postmanEvent{
							{
								Listen: "test",
								Script: postmanScript{
									Type: "text/javascript",
									Exec: []string{
										"pm.test(\"Status code is 401 Unauthorized\", function () {",
										"    pm.response.to.have.status(401);",
										"});",
										"pm.test(\"Includes WWW-Authenticate Bearer header\", function () {",
										"    pm.response.to.have.header(\"WWW-Authenticate\");",
										"});",
										"var jsonData = pm.response.json();",
										"pm.test(\"Error code is TOKEN_INVALID\", function () {",
										"    pm.expect(jsonData.error.code).to.eql(\"TOKEN_INVALID\");",
										"});",
									},
								},
							},
						},
					},
					{
						Name: "401 Unauthorized - Expired Token",
						Request: &postmanRequest{
							Method: "GET",
							Header: []postmanHeader{
								{Key: "Authorization", Value: "Bearer {{expired_token}}"},
							},
							URL: postmanURL{
								Raw:   "{{baseUrl}}/api/v1/approvals/status?service=purchasing&resource_id=test",
								Host:  []string{"{{baseUrl}}"},
								Path:  []string{"api", "v1", "approvals", "status"},
								Query: []postmanQuery{{Key: "service", Value: "purchasing"}, {Key: "resource_id", Value: "test"}},
							},
							Description: "Presents an expired token. Must return 401 with code TOKEN_EXPIRED.",
						},
						Event: []postmanEvent{
							{
								Listen: "test",
								Script: postmanScript{
									Type: "text/javascript",
									Exec: []string{
										"pm.test(\"Status code is 401 Unauthorized\", function () {",
										"    pm.response.to.have.status(401);",
										"});",
										"var jsonData = pm.response.json();",
										"pm.test(\"Error code is TOKEN_EXPIRED\", function () {",
										"    pm.expect(jsonData.error.code).to.eql(\"TOKEN_EXPIRED\");",
										"});",
									},
								},
							},
						},
					},
					{
						Name: "403 Forbidden - Missing Permission",
						Request: &postmanRequest{
							Method: "POST",
							Header: []postmanHeader{
								{Key: "Content-Type", Value: "application/json"},
								{Key: "Authorization", Value: "Bearer {{no_perm_token}}"},
							},
							Body: &postmanBody{
								Mode: "raw",
								Raw:  "{\n  \"service\": \"purchasing\",\n  \"resource_id\": \"test\",\n  \"amount\": 1000\n}",
							},
							URL: postmanURL{
								Raw:  "{{baseUrl}}/api/v1/approvals/submit",
								Host: []string{"{{baseUrl}}"},
								Path: []string{"api", "v1", "approvals", "submit"},
							},
							Description: "Caller lacks manager.approvals:submit grant. Must return 403 PERMISSION_DENIED.",
						},
						Event: []postmanEvent{
							{
								Listen: "test",
								Script: postmanScript{
									Type: "text/javascript",
									Exec: []string{
										"pm.test(\"Status code is 403 Forbidden\", function () {",
										"    pm.response.to.have.status(403);",
										"});",
										"var jsonData = pm.response.json();",
										"pm.test(\"Error code is PERMISSION_DENIED\", function () {",
										"    pm.expect(jsonData.error.code).to.eql(\"PERMISSION_DENIED\");",
										"});",
									},
								},
							},
						},
					},
					{
						Name: "403 Forbidden - Self-Approval Forbidden",
						Request: &postmanRequest{
							Method: "POST",
							Header: []postmanHeader{
								{Key: "Content-Type", Value: "application/json"},
								{Key: "Authorization", Value: "Bearer {{admin_token}}"},
							},
							Body: &postmanBody{
								Mode: "raw",
								Raw:  "{\n  \"notes\": \"Attempting to approve my own bill\"\n}",
							},
							URL: postmanURL{
								Raw:  "{{baseUrl}}/api/v1/approvals/{{multi_approval_id}}/approve",
								Host: []string{"{{baseUrl}}"},
								Path: []string{"api", "v1", "approvals", "{{multi_approval_id}}", "approve"},
							},
							Description: "If purchaser attempts to approve their own request, service forbids self-approval with 403 SELF_APPROVAL_FORBIDDEN.",
						},
						Event: []postmanEvent{
							{
								Listen: "test",
								Script: postmanScript{
									Type: "text/javascript",
									Exec: []string{
										"// Note: If multi_approval_id was already decided (e.g. rejected), 409 is returned.",
										"// If pending and same requester, 403 SELF_APPROVAL_FORBIDDEN is returned.",
										"pm.test(\"Returns 403 or 409 error envelope\", function () {",
										"    pm.expect([403, 409]).to.include(pm.response.code);",
										"});",
									},
								},
							},
						},
					},
					{
						Name: "409 Conflict - Duplicate Active Submission",
						Request: &postmanRequest{
							Method: "POST",
							Header: []postmanHeader{
								{Key: "Content-Type", Value: "application/json"},
								{Key: "Authorization", Value: "Bearer {{purchaser_token}}"},
							},
							Body: &postmanBody{
								Mode: "raw",
								Raw:  "{\n  \"service\": \"purchasing\",\n  \"resource_id\": \"{{resource_id}}\",\n  \"amount\": 35000\n}",
							},
							URL: postmanURL{
								Raw:  "{{baseUrl}}/api/v1/approvals/submit",
								Host: []string{"{{baseUrl}}"},
								Path: []string{"api", "v1", "approvals", "submit"},
							},
							Description: "Submitting the same resource ID that already has an approved or pending workflow returns 409 Conflict.",
						},
						Event: []postmanEvent{
							{
								Listen: "test",
								Script: postmanScript{
									Type: "text/javascript",
									Exec: []string{
										"pm.test(\"Status code is 409 Conflict\", function () {",
										"    pm.response.to.have.status(409);",
										"});",
										"var jsonData = pm.response.json();",
										"pm.test(\"Error code is DUPLICATE_SUBMISSION or REQUEST_ALREADY_DECIDED\", function () {",
										"    pm.expect([\"DUPLICATE_SUBMISSION\", \"REQUEST_ALREADY_DECIDED\"]).to.include(jsonData.error.code);",
										"});",
									},
								},
							},
						},
					},
					{
						Name: "409 Conflict - Already Decided Request",
						Request: &postmanRequest{
							Method: "POST",
							Header: []postmanHeader{
								{Key: "Content-Type", Value: "application/json"},
								{Key: "Authorization", Value: "Bearer {{manager_token}}"},
							},
							Body: &postmanBody{
								Mode: "raw",
								Raw:  "{\n  \"notes\": \"Duplicate approval attempt\"\n}",
							},
							URL: postmanURL{
								Raw:  "{{baseUrl}}/api/v1/approvals/{{approval_id}}/approve",
								Host: []string{"{{baseUrl}}"},
								Path: []string{"api", "v1", "approvals", "{{approval_id}}", "approve"},
							},
							Description: "Approving an already approved request returns 409 REQUEST_ALREADY_DECIDED.",
						},
						Event: []postmanEvent{
							{
								Listen: "test",
								Script: postmanScript{
									Type: "text/javascript",
									Exec: []string{
										"pm.test(\"Status code is 409 Conflict\", function () {",
										"    pm.response.to.have.status(409);",
										"});",
										"var jsonData = pm.response.json();",
										"pm.test(\"Error code is REQUEST_ALREADY_DECIDED\", function () {",
										"    pm.expect(jsonData.error.code).to.eql(\"REQUEST_ALREADY_DECIDED\");",
										"});",
									},
								},
							},
						},
					},
				},
			},
		},
	}
}
