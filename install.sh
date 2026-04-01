#!/usr/bin/env bash
set -euo pipefail

# SentinelFlow Installer
# Usage: ./install.sh [options]
#   ./install.sh                    # Install scanner + registry
#   ./install.sh --with-interceptors # Include runtime monitoring SDK
#   ./install.sh --global           # Install CLI globally

BOLD="\033[1m"
GREEN="\033[32m"
CYAN="\033[36m"
YELLOW="\033[33m"
RESET="\033[0m"

echo ""
echo -e "  ${CYAN}${BOLD}SentinelFlow${RESET} — AI Agent Governance"
echo -e "  ${BOLD}Installing...${RESET}"
echo ""

# Detect package manager
if command -v pnpm &>/dev/null; then
  PM="pnpm"
elif command -v yarn &>/dev/null; then
  PM="yarn"
elif command -v bun &>/dev/null; then
  PM="bun"
elif command -v npm &>/dev/null; then
  PM="npm"
else
  echo "Error: No package manager found. Install npm, pnpm, yarn, or bun."
  exit 1
fi

echo -e "  Package manager: ${BOLD}${PM}${RESET}"

# Install dependencies
echo -e "  Installing dependencies..."
$PM install

# Build all packages
echo -e "  Building packages..."
$PM run build

# Initialize SentinelFlow in current project if not already done
if [ ! -d ".sentinelflow" ]; then
  echo -e "  Initializing .sentinelflow/ directory..."
  node packages/cli/dist/index.js init .
fi

# Install CLI globally if requested
if [[ "${1:-}" == "--global" ]]; then
  echo -e "  Installing CLI globally..."
  if [ "$PM" = "npm" ] || [ "$PM" = "pnpm" ]; then
    $PM install -g .
  fi
fi

echo ""
echo -e "  ${GREEN}✓${RESET} ${BOLD}SentinelFlow installed!${RESET}"
echo ""
echo -e "  Next steps:"
echo -e "    ${BOLD}sentinelflow scan${RESET}          Scan for agents and issues"
echo -e "    ${BOLD}sentinelflow registry list${RESET}  View registered agents"
echo -e "    ${BOLD}sentinelflow scan --format md${RESET}  Generate governance report"
echo ""
echo -e "  Docs: ${CYAN}https://github.com/omswaroop/sentinelflow${RESET}"
echo ""
