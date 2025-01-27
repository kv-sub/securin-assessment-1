##CVE List Web Application
This is a simple web application that displays a list of CVEs (Common Vulnerabilities and Exposures) with their details such as CVE ID, description, CVSS score, published date, and modified date. The application includes pagination to navigate through multiple pages of CVEs.

##Features
##Display CVEs in a tabular format.
Pagination support to navigate through large datasets.
CSS styling for better UI/UX, including hover effects and alternating row colors.
Responsive design for mobile and desktop views.
##Requirements
Before you begin, ensure that you have the following installed on your system:

Python 3.6+ (for running the web application)
Flask (web framework for Python)
Jinja2 (templating engine for HTML rendering)
You can install the necessary Python packages via pip:


pip install flask
##Project Structure

CVE-List/
│
├── app.py                 # Main Python file to run the Flask application
├── templates/
│   └── index.html         # HTML template for displaying CVEs
├── static/
│   └── style.css          # CSS file for styling the page
├── requirements.txt       # Python dependencies
└── README.md              # This README file
##File Descriptions
app.py: Contains the Flask web application logic. It handles routes, requests, and serves the CVE data.
templates/index.html: The HTML template that displays the list of CVEs and supports pagination.
static/style.css: The stylesheet used to enhance the look and feel of the web page, with custom styles for the table, pagination, and responsive design.
##Setting Up the Application
Clone or download the repository to your local machine.

git clone https://github.com/your-username/CVE-List.git
cd CVE-List
##Install the necessary dependencies listed in requirements.txt (if using a virtual environment, activate it before proceeding).

pip install -r requirements.txt
##Run the Flask web application:

python app.py
The application will start running on http://127.0.0.1:5000/ (by default).

Open a web browser and go to http://127.0.0.1:5000/ to see the CVE list.
##Application Overview
1. Displaying CVEs:
The CVEs will be displayed in a table format with the following columns:

CVE ID
Description
CVSS Score
Published Date
Modified Date
2. Pagination:
At the bottom of the page, you can navigate between pages of CVEs using the "Previous" and "Next" links. The current page number is also displayed.

3. Styling:
The table has a responsive design and includes hover effects, alternating row colors, and improved spacing. The layout adjusts for different screen sizes, ensuring a good user experience across both desktop and mobile devices.

![image](https://github.com/user-attachments/assets/2522c7fa-5946-4b77-96da-08cbafbccf9f)


#How to Use
Navigating CVEs:

Use the pagination links to move through different pages of CVEs.
The "Previous" link will be disabled on the first page.
The "Next" link will take you to the next page of CVEs.
Adding/Editing Data:

To add or modify the CVE data, you would need to update the app.py file, where the data is served (currently, it's a static list in the example).
Customization
You can customize the CVE data and pagination as needed:

CVE Data: Update the cves list in app.py with your own data or connect to an external database/API to fetch CVE data dynamically.
Styling: Modify the style.css to change the appearance of the page according to your preferences.
License
This project is licensed under the MIT License - see the LICENSE file for details.

Acknowledgments
Flask: A lightweight WSGI web application framework in Python.
Jinja2: A modern and designer-friendly templating engine for Python.
CSS: Styles used to create a polished and user-friendly interface.
