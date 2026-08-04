---
description: Sign in to Microsoft Defender XDR using the system browser
allowed-tools: Bash(claude-defender-xdr-login *)
---
Run `claude-defender-xdr-login` in the terminal. It interactively configures the tenant and public-client application if needed, uses the system browser for Entra sign-in, validates the returned delegated ThreatHunting.Read.All token, and never accepts a client secret.
