env "local" {
  url = "postgres://postgres:RedDawn_84@localhost:5432/password_manager?sslmode=disable"
  migration {
    dir = "file://server/migrations"
  }
}