# CVE List Web Application

This is a simple web application that displays a list of CVEs (Common Vulnerabilities and Exposures) with their details such as CVE ID, description, CVSS score, published date, and modified date. The application includes pagination to navigate through multiple pages of CVEs.

## Features

- Display CVEs in a tabular format.
- Pagination support to navigate through large datasets.
- CSS styling for better UI/UX, including hover effects and alternating row colors.
- Responsive design for mobile and desktop views.
- API endpoints to filter CVEs based on year, CVSS score, and modified date.

## Requirements

Before you begin, ensure that you have the following installed on your system:

- **Python 3.6+** (for running the web application)
- **Flask** (web framework for Python)
- **Jinja2** (templating engine for HTML rendering)
- **requests** (for fetching CVE data from an external source)
- **mysql-connector-python** (for connecting to MySQL database)

You can install the necessary Python packages via pip:

    ```bash
    pip install flask requests mysql-connector-python

##File Descriptions
app.py: Contains the Flask web application logic. It handles routes, requests, and serves the CVE data.
templates/index.html: The HTML template that displays the list of CVEs and supports pagination.
static/style.css: The stylesheet used to enhance the look and feel of the web page, with custom styles for the table, pagination, and responsive design.
##Setting Up the Application
Clone or download the repository to your local machine.

git clone https://github.com/your-username/CVE-List.git
cd CVE-List
Install the necessary dependencies listed in requirements.txt (if using a virtual environment, activate it before proceeding).

pip install -r requirements.txt
Run the Flask web application:

python app.py

The application will start running on http://127.0.0.1:5000/ (by default).

Open a web browser and go to http://127.0.0.1:5000/ to see the CVE list.
## Application Overview
-1. Displaying CVEs:
-The CVEs will be displayed in a table format with the following columns:

-CVE ID 
-Description/
-CVSS Score/
-Published Date
-Modified Date

-2. Pagination:
At the bottom of the page, you can navigate between pages of CVEs using the "Previous" and "Next" links. The current page number is also displayed.

-3. Filtering CVEs:
You can use the following API endpoints to filter the CVEs based on different parameters:


![image](https://github.com/user-attachments/assets/a59843fc-687a-450d-a59a-30190c23d9ff)
![image](https://github.com/user-attachments/assets/12ccbd2a-3f2e-4399-bbb3-606f1e2414e3)


![image](https://github.com/user-attachments/assets/84810cfd-1035-4f02-a9c0-e03e26b8c5ae)



## How to Use
Navigating CVEs:

Use the pagination links to move through different pages of CVEs.
The "Previous" link will be disabled on the first page.
The "Next" link will take you to the next page of CVEs.
Filtering CVEs:

You can use the provided API endpoints to filter the CVEs by year, CVSS score, or modified date.
You can test these endpoints by visiting the corresponding URL in your browser or using tools like Postman.
Adding/Editing Data:

To add or modify the CVE data, you would need to update the app.py file, where the data is served (currently, it's a static list in the example).
Customization
You can customize the CVE data and pagination as needed:

CVE Data: Update the cves list in app.py with your own data or connect to an external database/API to fetch CVE data dynamically.
Styling: Modify the style.css to change the appearance of the page according to your preferences.
## License
This project is licensed under the MIT License - see the LICENSE file for details.

## Acknowledgments
Flask: A lightweight WSGI web application framework in Python.
Jinja2: A modern and designer-friendly templating engine for Python.
CSS: Styles used to create a polished and user-friendly interface.
requests: A simple HTTP library for Python, used to fetch CVE data from external sources.
MySQL: Used to store CVE details and serve them dynamically via the web interface.
