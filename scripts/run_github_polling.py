#!/usr/bin/env python3
"""Run CRA-AGENT in GitHub polling mode.

This script runs the agent in polling mode, which:
- Polls GitHub API for new commits
- No webhooks or ngrok needed
- Everything stays local on your machine

Usage:
    python scripts/run_github_polling.py

Prerequisites:
    1. Create a GitHub App (see below)
    2. Configure .env with GitHub credentials
    3. Configure config/repos.yaml with your repositories
"""

from __future__ import annotations

import sys
from pathlib import Path

# Add project root to path
sys.path.insert(0, str(Path(__file__).parent.parent))

import asyncio

from src.main import GitHubPollingAgent


def print_setup_guide() -> None:
    """Print setup guide for GitHub App."""
    print("""
╔══════════════════════════════════════════════════════════════════════════════╗
║                    CRA-AGENT GitHub Polling Mode Setup                       ║
╠══════════════════════════════════════════════════════════════════════════════╣
║                                                                              ║
║  This mode polls GitHub API for new commits - NO WEBHOOKS OR NGROK NEEDED!  ║
║                                                                              ║
╠══════════════════════════════════════════════════════════════════════════════╣
║  STEP 1: Create GitHub App (API access only, no webhooks)                   ║
╠══════════════════════════════════════════════════════════════════════════════╣
║                                                                              ║
║  1. Go to: https://github.com/settings/apps/new                             ║
║                                                                              ║
║  2. Fill in the form:                                                       ║
║     • GitHub App name: CRA-AGENT (or any unique name)                       ║
║     • Homepage URL: https://github.com/YOUR_USERNAME/CRA-AGENT              ║
║     • Webhook: UNCHECK "Active" (we don't need webhooks!)                   ║
║                                                                              ║
║  3. Permissions (Repository permissions):                                   ║
║     • Contents: Read-only                                                   ║
║     • Metadata: Read-only                                                   ║
║     • Pull requests: Read and write                                         ║
║     • Commit statuses: Read and write                                       ║
║                                                                              ║
║  4. Click "Create GitHub App"                                               ║
║                                                                              ║
╠══════════════════════════════════════════════════════════════════════════════╣
║  STEP 2: Generate Private Key                                               ║
╠══════════════════════════════════════════════════════════════════════════════╣
║                                                                              ║
║  1. On your app's settings page, scroll to "Private keys"                   ║
║  2. Click "Generate a private key"                                          ║
║  3. A .pem file will download                                               ║
║  4. Move it to your project:                                                ║
║     mv ~/Downloads/*.pem ./cra-agent.private-key.pem                        ║
║                                                                              ║
╠══════════════════════════════════════════════════════════════════════════════╣
║  STEP 3: Install App on Your Repositories                                   ║
╠══════════════════════════════════════════════════════════════════════════════╣
║                                                                              ║
║  1. Click "Install App" in the left sidebar                                 ║
║  2. Select your account                                                     ║
║  3. Choose "Only select repositories" and pick your repos                   ║
║  4. Click "Install"                                                         ║
║                                                                              ║
║  Note the Installation ID from the URL:                                     ║
║  https://github.com/settings/installations/12345678                         ║
║                                       ^^^^^^^^                              ║
║                                       This is your Installation ID          ║
║                                                                              ║
╠══════════════════════════════════════════════════════════════════════════════╣
║  STEP 4: Configure .env                                                     ║
╠══════════════════════════════════════════════════════════════════════════════╣
║                                                                              ║
║  Add these to your .env file:                                               ║
║                                                                              ║
║  # GitHub App Configuration                                                 ║
║  GITHUB_APP_ID=123456              # From app settings page                 ║
║  GITHUB_INSTALLATION_ID=12345678   # From installation URL                  ║
║  GITHUB_PRIVATE_KEY_PATH=./cra-agent.private-key.pem                        ║
║  GITHUB_WEBHOOK_SECRET=            # Leave empty - not needed!              ║
║                                                                              ║
╠══════════════════════════════════════════════════════════════════════════════╣
║  STEP 5: Configure Repositories                                             ║
╠══════════════════════════════════════════════════════════════════════════════╣
║                                                                              ║
║  Edit config/repos.yaml to list your repositories:                          ║
║                                                                              ║
║  repositories:                                                              ║
║    - name: your-org/your-repo                                               ║
║      enabled: true                                                          ║
║      branches:                                                              ║
║        - main                                                               ║
║        - develop                                                            ║
║                                                                              ║
╠══════════════════════════════════════════════════════════════════════════════╣
║  STEP 6: Run the Agent                                                      ║
╠══════════════════════════════════════════════════════════════════════════════╣
║                                                                              ║
║  python scripts/run_github_polling.py                                       ║
║                                                                              ║
║  Or: python -m src.main --mode github                                       ║
║                                                                              ║
║  The agent will poll GitHub every 60 seconds for new commits!               ║
║                                                                              ║
╚══════════════════════════════════════════════════════════════════════════════╝
""")


def check_configuration() -> bool:
    """Check if GitHub is configured."""
    from config.settings import get_settings

    settings = get_settings()

    if not settings.github_app_id:
        print("❌ GITHUB_APP_ID not set in .env")
        return False

    if not settings.github_installation_id:
        print("❌ GITHUB_INSTALLATION_ID not set in .env")
        return False

    if not settings.github_private_key_path.exists():
        print(f"❌ Private key not found at: {settings.github_private_key_path}")
        return False

    if not settings.github_repos_config.exists():
        print(f"❌ Repos config not found at: {settings.github_repos_config}")
        return False

    print("✅ Configuration looks good!")
    return True


def main() -> None:
    """Main entry point."""
    import argparse

    parser = argparse.ArgumentParser(description="Run CRA-AGENT in GitHub polling mode (no webhooks needed)")
    parser.add_argument(
        "--setup",
        action="store_true",
        help="Show setup guide",
    )
    parser.add_argument(
        "--check",
        action="store_true",
        help="Check configuration",
    )
    args = parser.parse_args()

    if args.setup:
        print_setup_guide()
        return

    if args.check:
        if check_configuration():
            print("\n✅ Ready to run! Execute: python scripts/run_github_polling.py")
        else:
            print("\n❌ Configuration incomplete. Run with --setup for guide.")
        return

    # Check configuration before running
    print("Checking configuration...")
    if not check_configuration():
        print("\n❌ Configuration incomplete. Run with --setup for guide.")
        sys.exit(1)

    print("\n🚀 Starting CRA-AGENT in GitHub polling mode...")
    print("   No webhooks or ngrok needed - everything stays local!\n")

    agent = GitHubPollingAgent()

    try:
        asyncio.run(agent.run())
    except KeyboardInterrupt:
        print("\n\n👋 Stopped by user")
        sys.exit(0)


if __name__ == "__main__":
    main()
