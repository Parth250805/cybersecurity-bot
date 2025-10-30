# Cybersecurity Bot 🛡️

A Python-based cybersecurity monitoring tool with real-time process detection, risk assessment, and alert system.

## Features

- 🔍 Real-time process monitoring
- 🚨 Suspicious process detection
- 📊 Risk assessment using ML
- 📧 Email alerts
- 🔔 Desktop notifications
- 🖥️ User-friendly GUI interface

## Setup

1. Clone the repository:
```bash
git clone https://github.com/Parth250805/cybersecurity-bot.git
cd cybersecurity-bot
```

2. Install dependencies:
```bash
pip install -r requirements.txt
```

3. Configure email alerts:
```bash
cp .env.template .env
```
Edit `.env` file with your email settings:
- For Gmail, use App Password (2FA required)
- Set recipient email
- Configure SMTP settings

4. Run the GUI:
```bash
python -m cybersecurity_bot.gui.simple_gui
```

## Configuration

Edit `cybersecurity_bot/config/config.yaml` to customize:
- Monitor interval
- Risk thresholds
- Process whitelist/blacklist
- Alert preferences

## Contributing

1. Fork the repository
2. Create a feature branch
3. Submit a pull request

## License

MIT License - See LICENSE file for details
