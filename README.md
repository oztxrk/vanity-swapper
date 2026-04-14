# Öztürk Swapper

Fast Discord vanity URL swapper using HTTP/2 sessions, password-based MFA authentication, and webhook notifications.

## Setup

1. Install [Node.js](https://nodejs.org/) (v18+)
2. Run `start.bat`

> If the `ozturk-mfa` folder is missing, it will be installed automatically.

## Usage

```
Token: <discord token>
Password: <account password>
Server ID: <server id to claim vanity for>
Webhook: <discord webhook url>
Vanity: <vanity to claim>
```

Once the inputs are provided, MFA is handled automatically. The vanity swap starts within 10 seconds and a webhook notification is sent on success.

## Files

```
ozturk-swapper/
├── index.js        # Main swapper
├── start.bat       # Launcher
├── package.json
└── ozturk-mfa/     # MFA library
```
