# 🛡️ Cybersecurity Bot GUI - Professional Edition

A modern, professional graphical interface for the Cybersecurity Bot featuring real-time monitoring, advanced threat detection, and intuitive system control with a sleek dark theme design.

## 🚀 Quick Start

### Option 1: Windows Batch File (Easiest)
```bash
# Double-click the batch file
start_gui.bat
```

### Option 2: Python Script
```bash
# Run the GUI launcher
python run_gui.py
```

### Option 3: Direct GUI
```bash
# Run GUI directly
python gui.py
```

## 🎯 Professional Features

### 🎨 Modern Design
- **Dark Theme**: Professional cybersecurity aesthetic
- **Card-based Layout**: Clean, organized interface
- **Smooth Animations**: Pulsing shield icon and status indicators
- **Responsive Design**: Adapts to different window sizes
- **Color-coded Elements**: Intuitive visual feedback

### 📊 Real-time Monitoring
- **System Status Cards**: Live CPU, RAM, and disk usage with color coding
- **Process Monitoring**: Real-time process scanning with risk assessment
- **Threat Detection**: Immediate threat identification with severity levels
- **Risk Scoring**: ML-based risk assessment with visual indicators

### 🎮 Advanced Control Panel
- **Modern Buttons**: Flat design with hover effects
- **Start/Stop Monitoring**: Intuitive bot control
- **Quick Scan**: On-demand threat scanning
- **Configuration Management**: Easy settings adjustment
- **Manual Override**: User control over automated actions

### 📈 Professional Dashboard
- **Process Tree**: Live process list with color-coded risk levels
- **Threat Counter**: Running count of detected threats
- **Activity Log**: Real-time event logging with timestamps
- **Status Indicators**: Clear visual feedback with animations
- **Header Status**: System-wide status display

### ⚙️ Configuration Options
- **Monitor Interval**: Adjustable scan frequency (1-60 seconds)
- **Risk Threshold**: Configurable threat level (0.1-1.0)
- **Email Alerts**: Toggle email notifications
- **Popup Alerts**: Toggle desktop notifications
- **Persistent Settings**: Configuration saved to YAML file

## 🖥️ GUI Components

### 1. System Status Panel
- Shows bot status (Running/Stopped)
- Displays system resource usage
- Real-time updates every 5 seconds

### 2. Control Buttons
- **🚀 Start Monitoring**: Begin continuous scanning
- **⏹️ Stop Monitoring**: Halt all monitoring
- **🔍 Quick Scan**: Perform single scan

### 3. Configuration Panel
- **Monitor Interval**: Seconds between scans (default: 5)
- **Risk Threshold**: ML risk score threshold (default: 0.7)
- **Email Alerts**: Enable/disable email notifications
- **Popup Alerts**: Enable/disable desktop popups
- **💾 Save Config**: Save settings to config.yaml

### 4. Real-time Monitoring
- **Process Tree**: Live list of detected processes
- **Threat Counter**: Running count of threats
- **Last Scan**: Timestamp of most recent scan

### 5. Activity Log
- **Real-time Events**: All bot activities
- **Timestamped Entries**: Precise timing
- **Color-coded Messages**: Easy to read
- **🗑️ Clear Log**: Reset log display

## 🎨 Professional Interface Design

### Modern Color Scheme
- **Primary Background**: Deep black (#0a0a0a) for professional look
- **Secondary Background**: Dark gray (#1a1a1a) for cards and panels
- **Tertiary Background**: Medium gray (#2a2a2a) for input fields
- **Accent Colors**: 
  - Blue (#00d4ff) for primary actions
  - Green (#00ff88) for success states
  - Red (#ff4757) for danger/warnings
  - Orange (#ffa502) for alerts
- **Text Colors**: White primary, gray secondary for hierarchy

### Professional Layout
- **Card-based Design**: Modern card components with accent lines
- **Two-column Layout**: Left panel for controls, right for monitoring
- **Responsive Grid**: Adapts to different window sizes
- **Consistent Spacing**: 20px padding throughout
- **Typography**: Segoe UI font family for modern Windows look
- **Visual Hierarchy**: Clear separation of functions with proper spacing

## 🔧 Technical Details

### Threading
- **Main Thread**: GUI updates and user interaction
- **Monitor Thread**: Background threat scanning
- **Queue System**: Thread-safe communication

### Real-time Updates
- **System Info**: Updated every 5 seconds
- **Process List**: Updated with each scan
- **Log Display**: Real-time event logging
- **Status Indicators**: Immediate feedback

### Error Handling
- **Graceful Degradation**: Continues on errors
- **User Feedback**: Clear error messages
- **Recovery**: Automatic retry mechanisms

## 📋 Usage Instructions

### Starting the Bot
1. Launch the GUI using any method above
2. Configure your settings in the Configuration panel
3. Click "🚀 Start Monitoring" to begin
4. Watch the real-time monitoring panel

### Monitoring Threats
1. The process tree shows all detected processes
2. Risk scores indicate threat level (0-1)
3. High-risk processes are auto-killed
4. All activities are logged in real-time

### Configuration
1. Adjust monitor interval (1-60 seconds)
2. Set risk threshold (0.1-1.0)
3. Toggle email and popup alerts
4. Click "💾 Save Config" to persist settings

### Stopping the Bot
1. Click "⏹️ Stop Monitoring" to halt
2. The bot will stop all scanning
3. Status will show "🔴 STOPPED"

## 🛠️ Troubleshooting

### Common Issues

**GUI won't start:**
- Check Python installation
- Install dependencies: `pip install -r requirements.txt`
- Ensure all modules are in the same directory

**No threats detected:**
- Check whitelist in detector.py
- Verify configuration settings
- Look at activity log for errors

**High CPU usage:**
- Increase monitor interval
- Check for infinite loops in logs
- Restart the application

**Email alerts not working:**
- Verify email configuration in emailer.py
- Check internet connection
- Test with popup alerts first

### Error Messages
- **"Error importing modules"**: Missing dependencies
- **"Monitoring error"**: Check system permissions
- **"Access denied"**: Run as administrator if needed

## 🔒 Security Notes

- The GUI runs with the same permissions as the command line version
- All detection logic remains unchanged
- GUI is just a visual interface to existing functionality
- No additional security risks introduced

## 🚀 Next Steps

This GUI provides a solid foundation for:
- Advanced dashboards
- Historical data visualization
- Multi-system monitoring
- Mobile app integration
- Cloud-based management

Enjoy your new cybersecurity bot interface! 🛡️
