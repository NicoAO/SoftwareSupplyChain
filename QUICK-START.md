# Quick Deployment Checklist

## 🚀 Deploy in 5 Minutes (Web Interface)

- [ ] Go to https://github.com/new
- [ ] Name: `codelocker-roi-dashboard`
- [ ] Public, Add README
- [ ] Click "Create repository"
- [ ] Click "Add file" → "Upload files"
- [ ] Drag `index.html` and `.gitignore`
- [ ] Commit changes
- [ ] Settings → Pages → Deploy from "main" branch → Save
- [ ] Wait 2-3 minutes
- [ ] Your site is live at `https://[username].github.io/codelocker-roi-dashboard/`

## 📝 Files to Upload

1. **index.html** (required) - Your dashboard
2. **.gitignore** (optional) - Ignore system files
3. **README.md** (optional) - Repository documentation

## 🌐 Custom Domain (Optional)

If you want `roi.codelocker.zevainc.com`:

1. GitHub Settings → Pages → Custom domain → Enter `roi.codelocker.zevainc.com`
2. DNS: Add CNAME record pointing to `[username].github.io`
3. Wait 15 minutes - 24 hours for DNS
4. Enable HTTPS in GitHub Pages settings

## 🔄 Update Your Site

**Web Interface:**
1. Go to repository → Click `index.html`
2. Click pencil icon (Edit)
3. Make changes → Commit
4. Wait 1-2 minutes

**Command Line:**
```bash
git add index.html
git commit -m "Update dashboard"
git push
```

## ✅ Verification

Your dashboard should have:
- Interactive calculator that updates in real-time
- Three working tabs (Problem, Calculator, Analysis)
- All links point to https://codelocker.zevainc.com/
- Charts and visualizations loading properly
- Mobile responsive design

## 🆘 Troubleshooting

**Site not loading?**
→ Wait 2-3 minutes, hard refresh (Ctrl+Shift+R)

**404 error?**
→ Make sure repository is Public and Pages is enabled

**Custom domain not working?**
→ Check DNS with `dig roi.codelocker.zevainc.com`

## 📊 Expected Performance

- Load time: < 2 seconds
- Works on all modern browsers
- Mobile friendly
- No backend required
- Zero maintenance

---

**You're done!** Share your live URL with Zeva and your capstone advisor.
