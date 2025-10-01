package password_manager

//generate proto
//go:generate buf generate

//apply atlas migrations
//go:generate atlas migrate apply --env local

//generate sqlc code
//go:generate sqlc generate -f ./server/repository/sqlc/sqlc.yaml
