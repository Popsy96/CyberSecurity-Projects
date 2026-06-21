@echo off
cd Cyber-Threat-Intelligence-Dashboard
python main.py
cd ..
copy Cyber-Threat-Intelligence-Dashboard\data.json docs\data.json
git add docs/data.json
git commit -m "Update dashboard data %date%"
git push
echo Done! Wait 60 seconds then refresh your live site.
pause