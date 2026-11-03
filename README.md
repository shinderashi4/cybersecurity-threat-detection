Cybersecurity Incident Response and Threat Hunting

Project Overview

This project is a cybersecurity threat detection and incident response application. It analyzes log data to identify suspicious activities and displays the results through a Streamlit dashboard.

Features

•⁠  ⁠Detects suspicious login attempts.
•⁠  ⁠Identifies possible directory traversal and SQL injection patterns.
•⁠  ⁠Detects suspicious shell or remote code execution patterns.
•⁠  ⁠Displays threat detection results on a dashboard.
•⁠  ⁠Generates incident reports.
•⁠  ⁠Provides a summary of detected security events.

Technologies Used

•⁠  ⁠Python
•⁠  ⁠Streamlit
•⁠  ⁠Pandas
•⁠  ⁠Docker

Project Files

•⁠  ⁠app.py — Runs the Streamlit dashboard.
•⁠  ⁠detector.py — Contains the threat detection logic.
•⁠  ⁠requirements.txt — Lists the Python packages required.
•⁠  ⁠Dockerfile — Defines how to build and run the project using Docker.

How to Run the Project

1.⁠ ⁠Install dependencies

pip install -r requirements.txt

2.⁠ ⁠Run the application

python -m streamlit run app.py

3.⁠ ⁠Open the dashboard

Open the local URL shown in the terminal, usually:

http://localhost:8501

Docker

To build the Docker image:

docker build -t cybersecurity-app .

To run the application:

docker run -p 8501:8501 cybersecurity-app

Then open http://localhost:8501 in your browser.

Note

The project demonstrates threat detection using simulated or provided log data. It is intended for educational and demonstration purposes.