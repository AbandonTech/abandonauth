import classy_config

classy_config.register_config(".env")

from abandonauth.run import app
