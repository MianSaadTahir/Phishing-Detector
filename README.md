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

- **URL and File Scanning**: Scan links, QR code and uploaded files for malware and phishing threats.
- **Pawned Detection**: Uses HaveIBeenPwned API to detect breached emails and passwords.
- **User Authentication**: Secure sign-up/login system with hashed passwords.
- **Database Architecture**: SQLite used for storing users, phishing URLs, IPs, and breach data.

## Screenshots

<img src="assets/1.PNG" alt="Screenshot" width="75%">
<img src="assets/2.PNG" alt="Screenshot" width="75%">
<img src="assets/3.PNG" alt="Screenshot" width="75%">
<img src="assets/4.PNG" alt="Screenshot" width="75%">
<img src="assets/5.PNG" alt="Screenshot" width="75%">
<img src="assets/6.PNG" alt="Screenshot" width="75%">
<img src="assets/7.PNG" alt="Screenshot" width="75%">
<img src="assets/8.PNG" alt="Screenshot" width="75%">
<img src="assets/9.PNG" alt="Screenshot" width="75%">

## Usage

1. Clone the repository:
   `git clone https://github.com/yourusername/threat-guard.git`
2. Navigate to the project directory:
   `cd threat-guard`
3. Install required dependencies
4. Run the app by typing `python app.py` in terminal.

## Documentation

For a detailed overview of the gameplay mechanics and features, refer to the [Documentation](./documentation) in the repository.

## Technologies Used

- Python
- Flask
- SQLite
- Flask-Limiter
- Jinja2
- HTML5
- CSS3
- JS
- VirusTotal API
- HaveIBeenPwned API

## Contributing

Contributions, issues, and feature requests are welcome!  
Feel free to check out the [issues page](https://github.com/miansaadtahir/Threat-Guard/issues) for more information.

## License

Distributed under the MIT License. See [LICENSE](./LICENSE) for more details.
