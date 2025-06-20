# Threat Guard

**Threat Guard** is a cyber safety web app built using Python's Flask framework. It integrates real-time scanning of URLs, QR codes and files using the VirusTotal API, checks for compromised passwords via HaveIBeenPwned, blocks DDoS attempts through rate limiting, and stores users data and phishing-related data securely using SQLite databases.

## Table of Contents
- [Features](#features)
- [Screenshots](#screenshots)
- [Usage](#usage)
- [Documentation](#documentation)
- [Technologies Used](#technologies-used)
- [Contributing](#contributing)
- [License](#license)

## Features
- **URL and File Scanning**: Scan links, QR codes, and uploaded files for malware and phishing threats.
- **Pawned Detection**: Check if emails or passwords have been exposed in data breaches using the HaveIBeenPwned API.
- **User Authentication**: Secure sign-up/login system with hashed passwords.
- **Database Architecture**: SQLite used for storing users, phishing URLs, IPs, and breach data.

## Screenshots
<img src="assets/2.png" alt="Screenshot" width="75%">
<img src="assets/3.png" alt="Screenshot" width="75%">
<img src="assets/4.png" alt="Screenshot" width="75%">
<img src="assets/10.png" alt="Screenshot" width="75%">
<img src="assets/6.png" alt="Screenshot" width="75%">
<img src="assets/8.png" alt="Screenshot" width="75%">
<img src="assets/9.png" alt="Screenshot" width="75%">

## Usage
1. Clone the repository:
   `git clone https://github.com/miansaadtahir/threat-guard.git`
2. Navigate to the project directory:
   `cd threat-guard`
3. Open terminal in the project directory.
4. Install required dependencies:
   `pip install -r requirements.txt`
5. Create a `.env` file in the root directory and add your VirusTotal API key.
6. Run the application:
   `python app.py`
7. Open the local address shown in the terminal `(e.g., http://127.0.0.1:5000)` in your browser to start using the app.

## Documentation
For a detailed overview of the project, refer to the [Documentation](./documentation) in the repository.

## Technologies Used
- Python
- Flask
- SQLite
- Jinja2
- HTML5
- CSS3
- JS

## Contributing
Contributions, issues, and feature requests are welcome!  
Feel free to check out the [issues page](https://github.com/miansaadtahir/Threat-Guard/issues) for more information.
