package password_manager

//go:generate buf generate
//go:generate atlas migrate apply --env local
//go:generate sqlc generate -f ./server/repository/sqlc/sqlc.yaml
