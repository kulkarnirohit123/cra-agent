#!/usr/bin/env python3
"""GitHub App setup script for CRA-AGENT.

This script helps you set up a GitHub App for the CRA-AGENT:
1. Creates a GitHub App using the `gh` CLI
2. Generates a private key
3. Configures webhook settings
4. Outputs the required environment variables

Prerequisites:
- GitHub CLI (`gh`) installed and authenticated
- A public URL for your webhook server (e.g., ngrok)

Usage:
    python scripts/setup_github_app.py --webhook-url https://your-url.ngrok.io
"""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
import tempfile
from pathlib import Path


def run_command(cmd: list[str], check: bool = True) -> subprocess.CompletedProcess:
    """Run a shell command and return the result."""
    print(f"Running: {' '.join(cmd)}")
    result = subprocess.run(cmd, capture_output=True, text=True)
    if check and result.returncode != 0:
        print(f"Error: {result.stderr}")
        sys.exit(1)
    return result


def check_gh_cli() -> bool:
    """Check if GitHub CLI is installed and authenticated."""
    try:
        result = run_command(["gh", "auth", "status"], check=False)
        if result.returncode != 0:
            print("Error: GitHub CLI is not authenticated.")
            print("Run: gh auth login")
            return False
        return True
    except FileNotFoundError:
        print("Error: GitHub CLI (gh) is not installed.")
        print("Install from: https://cli.github.com/")
        return False


def create_github_app(
    name: str,
    webhook_url: str,
    webhook_secret: str,
) -> dict:
    """Create a GitHub App using the GitHub API.

    Args:
        name: App name.
        webhook_url: Webhook URL.
        webhook_secret: Webhook secret.

    Returns:
        App data including ID and client ID.
    """
    # App manifest for creation
    manifest = {
        "name": name,
        "url": "https://github.com/cra-agent",
        "hook_attributes": {
            "url": f"{webhook_url}/webhook/github",
            "active": True,
        },
        "redirect_url": webhook_url,
        "description": "CRA-AGENT: Automated CRA compliance scanning",
        "public": False,
        "default_events": [
            "push",
            "pull_request",
        ],
        "default_permissions": {
            "contents": "read",
            "metadata": "read",
            "pull_requests": "write",
            "statuses": "write",
            "issues": "write",
        },
    }

    # Write manifest to temp file
    with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as tmp:
        tmp.write(json.dumps(manifest))
        manifest_path = Path(tmp.name)

    print(f"\nCreating GitHub App '{name}'...")
    print(f"Webhook URL: {webhook_url}/webhook/github")

    # Use gh api to create the app
    result = run_command(
        [
            "gh",
            "api",
            "-X",
            "POST",
            "/app-manifests",
            "-f",
            f"manifest=@{manifest_path}",
        ],
        check=False,
    )

    if result.returncode != 0:
        print("Note: Automatic app creation requires manual setup.")
        print("\nPlease create the GitHub App manually:")
        print("1. Go to: https://github.com/settings/apps/new")
        print(f"2. Name: {name}")
        print(f"3. Webhook URL: {webhook_url}/webhook/github")
        print(f"4. Webhook secret: {webhook_secret}")
        print("5. Permissions:")
        print("   - Contents: Read-only")
        print("   - Metadata: Read-only")
        print("   - Pull requests: Read and write")
        print("   - Commit statuses: Read and write")
        print("   - Issues: Read and write")
        print("6. Subscribe to events:")
        print("   - Push")
        print("   - Pull request")
        print("\nAfter creating the app, update .env with the credentials.")
        return {}

    return json.loads(result.stdout)


def generate_private_key(app_id: str) -> str:
    """Generate a private key for the GitHub App.

    Args:
        app_id: GitHub App ID.

    Returns:
        Path to the generated private key file.
    """
    key_path = Path(f"./cra-agent-{app_id}.private-key.pem")

    print("\nGenerating private key...")
    print("Note: You need to generate the private key from GitHub:")
    print(f"1. Go to: https://github.com/settings/apps/{app_id}")
    print("2. Click 'Generate a private key'")
    print(f"3. Save it as: {key_path}")

    return str(key_path)


def print_env_template(
    app_id: str = "",
    installation_id: str = "",
    webhook_secret: str = "",
    private_key_path: str = "",
) -> None:
    """Print the environment variables template.

    Args:
        app_id: GitHub App ID.
        installation_id: Installation ID.
        webhook_secret: Webhook secret.
        private_key_path: Path to private key file.
    """
    print("\n" + "=" * 60)
    print("ENVIRONMENT VARIABLES")
    print("=" * 60)
    print("\nAdd these to your .env file:\n")

    env_vars = f"""# GitHub App Configuration
GITHUB_APP_ID={app_id or "<your-app-id>"}
GITHUB_INSTALLATION_ID={installation_id or "<your-installation-id>"}
GITHUB_WEBHOOK_SECRET={webhook_secret or "<your-webhook-secret>"}
GITHUB_PRIVATE_KEY_PATH={private_key_path or "./cra-agent.private-key.pem"}

# Optional: GitHub API URL (for GitHub Enterprise)
# GITHUB_API_URL=https://github.example.com/api/v3
"""
    print(env_vars)

    print("\n" + "=" * 60)
    print("NEXT STEPS")
    print("=" * 60)
    print("""
1. Update .env with the GitHub App credentials
2. Install the app on your repositories:
   - Go to: https://github.com/settings/apps/<your-app>/installations
   - Click 'Install' and select repositories

3. Start the webhook server:
   docker compose up -d webhook

4. Test the webhook:
   - Go to your GitHub App settings
   - Click 'Ping' to send a test webhook
   - Check logs: docker compose logs webhook

5. Push code to your repositories to trigger scans!
""")


def main() -> None:
    """Main entry point."""
    parser = argparse.ArgumentParser(description="Setup GitHub App for CRA-AGENT")
    parser.add_argument(
        "--name",
        default="CRA-AGENT",
        help="GitHub App name (default: CRA-AGENT)",
    )
    parser.add_argument(
        "--webhook-url",
        required=True,
        help="Public URL for webhook server (e.g., https://xxx.ngrok.io)",
    )
    parser.add_argument(
        "--webhook-secret",
        default="cra-agent-webhook-secret",
        help="Webhook secret (default: cra-agent-webhook-secret)",
    )
    parser.add_argument(
        "--skip-create",
        action="store_true",
        help="Skip app creation (just print env template)",
    )

    args = parser.parse_args()

    print("=" * 60)
    print("CRA-AGENT GitHub App Setup")
    print("=" * 60)

    # Check prerequisites
    if not args.skip_create:
        if not check_gh_cli():
            sys.exit(1)

    if args.skip_create:
        print_env_template(
            webhook_secret=args.webhook_secret,
        )
        return

    # Create the GitHub App
    app_data = create_github_app(
        name=args.name,
        webhook_url=args.webhook_url,
        webhook_secret=args.webhook_secret,
    )

    if app_data:
        app_id = app_data.get("id", "")
        private_key_path = generate_private_key(str(app_id))

        print_env_template(
            app_id=str(app_id),
            webhook_secret=args.webhook_secret,
            private_key_path=private_key_path,
        )
    else:
        print_env_template(
            webhook_secret=args.webhook_secret,
        )


if __name__ == "__main__":
    main()
