# GitHub Deployment Guide

## Step-by-Step Instructions

### Option 1: GitHub Web Interface (Easiest - No Git Required)

**Perfect if you're not familiar with Git/command line**

1. **Create a GitHub account** (if you don't have one)
   - Go to https://github.com/signup
   - Follow the signup process

2. **Create a new repository**
   - Click the "+" icon in top right → "New repository"
   - Repository name: `codelocker-roi-dashboard` (or any name you prefer)
   - Description: "ROI calculator for CodeLocker supply chain security"
   - Choose "Public" (required for free GitHub Pages)
   - Check "Add a README file"
   - Click "Create repository"

3. **Upload the files**
   - In your new repository, click "Add file" → "Upload files"
   - Drag and drop these files:
     - `index.html` (your dashboard)
     - `.gitignore`
   - Or click "choose your files" to browse
   - Add a commit message: "Initial dashboard deployment"
   - Click "Commit changes"

4. **Update the README**
   - Click on `README.md` in your repository
   - Click the pencil icon (Edit this file)
   - Replace the content with the `README.md` I provided
   - Click "Commit changes"

5. **Enable GitHub Pages**
   - Go to your repository Settings (gear icon)
   - Scroll down to "Pages" section in the left sidebar
   - Under "Source", select "Deploy from a branch"
   - Under "Branch", select "main" and "/ (root)"
   - Click "Save"

6. **Wait for deployment** (2-3 minutes)
   - GitHub will build and deploy your site
   - Refresh the Pages settings page
   - You'll see a message: "Your site is live at https://[your-username].github.io/codelocker-roi-dashboard/"

7. **Visit your live site!**
   - Click the URL to see your deployed dashboard
   - Share this URL with anyone

### Option 2: Command Line (For Git Users)

```bash
# 1. Navigate to the deployment folder
cd /path/to/codelocker-deployment

# 2. Initialize Git repository
git init

# 3. Add all files
git add .

# 4. Create first commit
git commit -m "Initial dashboard deployment"

# 5. Create repository on GitHub
# Go to https://github.com/new and create a repository named "codelocker-roi-dashboard"

# 6. Link your local repository to GitHub
git remote add origin https://github.com/YOUR-USERNAME/codelocker-roi-dashboard.git

# 7. Push to GitHub
git branch -M main
git push -u origin main

# 8. Enable GitHub Pages
# Go to repository Settings → Pages → Deploy from branch "main" → Save
```

## Custom Domain Setup (Optional)

If you want to use `roi.codelocker.zevainc.com` instead of the GitHub URL:

1. **In your repository Settings → Pages:**
   - Enter your custom domain: `roi.codelocker.zevainc.com`
   - Click "Save"

2. **In your DNS provider (where you manage zevainc.com):**
   - Add a CNAME record:
     - Name: `roi.codelocker`
     - Value: `YOUR-USERNAME.github.io`
     - TTL: 3600 (or default)

3. **Wait for DNS propagation** (can take up to 24 hours, usually 15 minutes)

4. **Enable HTTPS** (in GitHub Pages settings once DNS is verified)

## Updating Your Dashboard

### Via Web Interface:
1. Go to your repository on GitHub
2. Click on `index.html`
3. Click the pencil icon (Edit this file)
4. Make your changes
5. Scroll down, add commit message
6. Click "Commit changes"
7. Wait 1-2 minutes for automatic redeployment

### Via Command Line:
```bash
# Make changes to index.html locally
# Then:
git add index.html
git commit -m "Update dashboard with new data"
git push
```

## Troubleshooting

### Site not loading?
- Make sure repository is Public
- Check that GitHub Pages is enabled in Settings
- Wait 2-3 minutes after enabling Pages
- Clear your browser cache

### Changes not appearing?
- Wait 1-2 minutes after pushing
- Hard refresh: Ctrl+Shift+R (Windows) or Cmd+Shift+R (Mac)
- Check the Actions tab to see if deployment succeeded

### Custom domain not working?
- Verify DNS settings with `dig roi.codelocker.zevainc.com`
- Wait for DNS propagation (up to 24 hours)
- Make sure CNAME record points to `USERNAME.github.io` (not the full URL)

## Repository Structure

```
codelocker-roi-dashboard/
├── index.html          # Your complete dashboard
├── README.md           # Repository documentation
└── .gitignore          # Files to ignore in version control
```

## GitHub Pages URLs

Your dashboard will be available at:
- **Default**: `https://YOUR-USERNAME.github.io/codelocker-roi-dashboard/`
- **With custom domain**: `https://roi.codelocker.zevainc.com/` (if configured)

## Benefits of GitHub Pages

✅ Free hosting  
✅ HTTPS by default  
✅ Automatic deployment on push  
✅ Custom domain support  
✅ Version control for all changes  
✅ 100% uptime (backed by GitHub's infrastructure)  
✅ Fast global CDN  

## Next Steps After Deployment

1. **Test the live site** thoroughly
2. **Share the URL** with your team at Zeva
3. **Update the README** with the actual live URL
4. **Add Google Analytics** (if needed) by editing index.html
5. **Present to your advisor** for capstone approval

---

**Questions?** Check GitHub's official Pages documentation: https://docs.github.com/en/pages
