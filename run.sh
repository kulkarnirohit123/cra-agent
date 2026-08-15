#!/bin/bash
# =============================================================================
# CRA-AGENT Run Script
# =============================================================================
# This script helps run the CRA-AGENT services locally.
#
# Usage:
#   ./run.sh dashboard    # Start only the dashboard
#   ./run.sh agent        # Start only the agent
#   ./run.sh webhook      # Start only the webhook server
#   ./run.sh all          # Start all services
#   ./run.sh stop         # Stop all services
#   ./run.sh logs         # View logs

set -e

# Check if docker compose is available (V2 syntax)
if command -v docker &> /dev/null && docker compose version &> /dev/null; then
    COMPOSE_CMD="docker compose"
elif command -v docker-compose &> /dev/null; then
    COMPOSE_CMD="docker-compose"
else
    echo "Error: Docker Compose is not installed."
    echo "Please install Docker Desktop from https://www.docker.com/products/docker-desktop"
    exit 1
fi

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Function to print colored output
print_info() {
    echo -e "${GREEN}[INFO]${NC} $1"
}

print_warn() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

print_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Check if .env file exists
check_env() {
    if [ ! -f .env ]; then
        print_warn ".env file not found. Creating from .env.example..."
        cp .env.example .env
        print_warn "Please edit .env with your actual credentials before running."
    fi
}

# Create data directory
create_data_dir() {
    mkdir -p data
}

# Main command handler
case "${1:-help}" in
    dashboard)
        check_env
        create_data_dir
        print_info "Starting dashboard on http://localhost:8501"
        $COMPOSE_CMD up -d dashboard
        print_info "Dashboard is running at http://localhost:8501"
        ;;
    
    agent)
        check_env
        create_data_dir
        print_info "Starting CRA agent..."
        $COMPOSE_CMD up -d agent
        print_info "Agent is running. View logs with: $COMPOSE_CMD logs -f agent"
        ;;
    
    webhook)
        check_env
        create_data_dir
        print_info "Starting webhook server on http://localhost:8080"
        $COMPOSE_CMD up -d webhook
        print_info "Webhook server is running at http://localhost:8080"
        ;;
    
    all)
        check_env
        create_data_dir
        print_info "Starting all services..."
        $COMPOSE_CMD up -d
        print_info "All services are running:"
        print_info "  - Dashboard: http://localhost:8501"
        print_info "  - Webhook:   http://localhost:8080"
        print_info "  - Agent:     Running in background"
        ;;
    
    stop)
        print_info "Stopping all services..."
        $COMPOSE_CMD down
        print_info "All services stopped."
        ;;
    
    logs)
        $COMPOSE_CMD logs -f ${2:-}
        ;;
    
    status)
        $COMPOSE_CMD ps
        ;;
    
    build)
        print_info "Building Docker images..."
        $COMPOSE_CMD build
        print_info "Build complete."
        ;;
    
    local-dashboard)
        # Run dashboard locally without Docker
        print_info "Starting dashboard locally..."
        print_info "Make sure you have installed dependencies: pip install -e '.[dev]'"
        streamlit run src/dashboard/app.py --server.port 8501
        ;;
    
    local-webhook)
        # Run webhook server locally without Docker
        print_info "Starting webhook server locally..."
        print_info "Make sure you have installed dependencies: pip install -e '.[dev]'"
        uvicorn src.webhook.server:app --host 0.0.0.0 --port 8080 --reload
        ;;
    
    help|*)
        echo "CRA-AGENT Run Script"
        echo ""
        echo "Usage: ./run.sh <command>"
        echo ""
        echo "Docker Commands:"
        echo "  dashboard    Start only the dashboard (http://localhost:8501)"
        echo "  agent        Start only the agent"
        echo "  webhook      Start only the webhook server (http://localhost:8080)"
        echo "  all          Start all services"
        echo "  stop         Stop all services"
        echo "  logs         View logs (optionally: ./run.sh logs <service>)"
        echo "  status       Show service status"
        echo "  build        Build Docker images"
        echo ""
        echo "Local Commands (no Docker):"
        echo "  local-dashboard   Run dashboard locally with Streamlit"
        echo "  local-webhook     Run webhook server locally with Uvicorn"
        echo ""
        echo "Examples:"
        echo "  ./run.sh dashboard     # Start dashboard only"
        echo "  ./run.sh all           # Start all services"
        echo "  ./run.sh logs agent    # View agent logs"
        echo "  ./run.sh local-dashboard  # Run dashboard without Docker"
        ;;
esac