# Railway Deployment Guide

## Quick Start

1. **Connect your GitHub repository to Railway:**
   - Go to [railway.app](https://railway.app)
   - Click "New Project"
   - Select "Deploy from GitHub repo"
   - Choose your repository

2. **Railway will auto-detect:**
   - Python runtime
   - `requirements.txt` for dependencies
   - `run.py` as the start command (or use Procfile)

3. **Environment Variables (if needed):**
   - Railway automatically sets `PORT` environment variable
   - No additional configuration needed!

4. **Deploy:**
   - Railway will automatically build and deploy
   - Your app will be live at `https://your-app-name.up.railway.app`

## What Railway Auto-Detects

- ✅ Python runtime (from `requirements.txt`)
- ✅ Start command (from `Procfile` or `run.py`)
- ✅ Port binding (from `PORT` environment variable)

## Differences from Render

- **No Procfile needed** (but it works if you have one)
- **Auto-detects Python** - no manual configuration
- **Better WebSocket support** - no worker timeout issues
- **More reliable** - Pro plan has no timeouts

## Database

- Railway provides PostgreSQL by default
- Your current SQLite database will work, but consider migrating to PostgreSQL for production
- SQLite files are stored in the filesystem (persists between deployments)

## Custom Domain

1. Go to your Railway project
2. Click "Settings"
3. Click "Generate Domain" or add your custom domain
4. Railway provides free SSL certificates

## Monitoring

- Railway dashboard shows logs in real-time
- No need for external logging services
- Built-in metrics and monitoring

## Notes

- Railway Pro plan has no worker timeouts
- WebSocket connections work reliably
- No need for special configuration

