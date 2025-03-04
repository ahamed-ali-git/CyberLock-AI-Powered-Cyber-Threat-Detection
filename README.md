# CyberLock: AI-Powered Cyber Threat Detection

## 🔒 Overview
CyberLock is a comprehensive cybersecurity tool designed to detect and analyze various cyber threats, including phishing emails, suspicious URLs, and scam patterns. It provides an interactive interface with real-time analysis and educational insights to help users understand and prevent online attacks. The project leverages machine learning, pattern recognition, and web scraping techniques to enhance security awareness and protection.

## 🚀 Features
- **Email Attack Detection**: Identifies phishing, scam, and malware-laden emails using keyword analysis and pattern matching.
- **URL Analyzer**: Evaluates the legitimacy of URLs to detect malicious websites.
- **Cyber Attack Encyclopedia**: Provides detailed information on various cyber attack types, including their mechanisms, consequences, and prevention methods.
- **Scam Pattern Detection**: Recognizes common scam messages and fraud patterns based on predefined keywords and hashed scam indicators.
- **Interactive Dashboard**: User-friendly GUI for easy navigation and real-time threat analysis.

## 🛠️ Installation
1. Clone the repository:
   ```sh
   git clone https://github.com/your-repo/cyberlock.git
   cd cyberlock
   ```
2. Install the required dependencies:
   ```sh
   pip install -r requirements.txt
   ```
3. Run the application:
   ```sh
   python Main.py
   ```

## 📁 Project Structure
```
cyberlock/
│── About.py             # Cyber attack encyclopedia with data visualization
│── demo.py              # URL analysis tool with domain verification
│── Email_Attack.py      # Email spam and phishing detection module
│── Main.py              # Main dashboard to access all functionalities
│── scam_patterns.py     # Scam pattern recognition and hashing
│── cyberlock ML report.pdf  # Documentation and project report
└── requirements.txt     # Required dependencies
```

## 📖 How It Works
- **Email Attack Detection**: Extracts text from emails, checks for predefined scam patterns, and classifies them as spam or ham.
- **URL Analysis**: Uses web scraping and dataset comparison to verify whether a URL is malicious or legitimate.
- **Cyber Attack Encyclopedia**: Displays categorized attack types with a dynamic UI and prevention tips.
- **Scam Pattern Recognition**: Compares text messages against a hashed scam pattern database for fraud detection.

## 📌 Dependencies
- Python 3.x
- CustomTkinter
- Matplotlib
- Pandas
- BeautifulSoup4
- Requests
- Tkinter

## 🎯 Future Enhancements
- Integration with AI-based models for advanced threat detection
- Real-time phishing email detection with ML algorithms
- Cloud-based reporting and alert system

## 🤝 Contributing
Feel free to fork the repository and submit pull requests. For major changes, open an issue first to discuss the proposed modifications.

## 🏆 Credits
Developed by **Ahamed Ali Z**

📧 Contact: ahamedaliz2004@gmail.com  
🌐 GitHub: [ahamed-ali-git](https://github.com/ahamed-ali-git)   

