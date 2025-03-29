# Old World PBC Discord Bot

This repository contains a simple Discord bot that integrates with an HTTP server to notify players of their turn in Old World Play by Cloud games.

The bot was inspired by [roze](https://roze.run) but that provides equivalent functionality for Civ6 games.

Discord Integration:

Registers the /owturn command with subcommands:

* iam: Associates an in-game name with the invoking Discord user's ID.

* start: Start turn notifications for a specified game, using the current channel/thread for notifications

# Prerequisites

Go 1.16 or later

A Discord Bot account with:

DISCORD_BOT_TOKEN

DISCORD_APP_ID

DISCORD_GUILD_ID

# License

This repository is licensed under the MIT License. Feel free to extend the bot and to run it on your own servers.
