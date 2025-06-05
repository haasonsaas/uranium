#!/bin/bash

# Setup script for Uranium Vault database

set -e

echo "🔧 Setting up Uranium Vault database..."

# Check if sqlite3 is installed
if ! command -v sqlite3 &> /dev/null; then
    echo "❌ sqlite3 is required but not installed. Please install it."
    exit 1
fi

# Create database if it doesn't exist
if [ ! -f uranium_vault.db ]; then
    echo "📁 Creating database..."
    sqlite3 uranium_vault.db < migrations/001_initial_schema.sql
    echo "✅ Database created"
else
    echo "ℹ️  Database already exists"
fi

# Check if sqlx-cli is installed
if command -v sqlx &> /dev/null; then
    echo "🔄 Preparing SQLx offline data..."
    export DATABASE_URL="sqlite://uranium_vault.db"
    
    # Run migrations
    sqlx migrate run
    
    # Prepare offline query data
    cd uranium-vault && cargo sqlx prepare && cd ..
    echo "✅ SQLx offline data prepared"
else
    echo "⚠️  sqlx-cli not installed. Install with: cargo install sqlx-cli"
    echo "   Without it, uranium-vault will only compile with a live database"
fi

echo "✅ Database setup complete!"