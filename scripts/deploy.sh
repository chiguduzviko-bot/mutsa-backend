#!/usr/bin/env bash
set -euo pipefail

echo "Logging into Railway..."
railway login

echo "Linking project..."
railway link

echo "Running database migrations..."
railway run flask --app run.py db upgrade

echo "Deployment helper completed."
