package config

type Config struct {
	Database Database
	Discord  DiscordOAuth
	GitHub   GitHubOAuth
	Jwt      Jwt
	Server   Server
}
