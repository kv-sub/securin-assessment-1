import requests
import mysql.connector
from flask import Flask, jsonify, request, render_template, redirect, url_for
from datetime import datetime, timedelta
import threading
import time

app = Flask(__name__)

# MySQL connection
def get_db_connection():
    return mysql.connector.connect(
        host='localhost',
        user='root',
        password='Aravind@2003',
        database='cve_database'
    )

# Create the table for storing CVE details (checks if it exists before creation)
def create_table():
    conn = get_db_connection()
    cursor = conn.cursor()
    table_creation_query = table_creation_query = """
    CREATE TABLE IF NOT EXISTS cve_details (
        cve_id VARCHAR(255) PRIMARY KEY,
        description TEXT NOT NULL,
        published_date DATETIME NOT NULL,
        modified_date DATETIME NOT NULL,
        cvss_score FLOAT NOT NULL,
        cvss_v2_score FLOAT,
        year INT NOT NULL,
        status VARCHAR(50) NOT NULL DEFAULT 'new'  -- Default status set to 'new'
    );
    """
    cursor.execute(table_creation_query)
    conn.commit()
    cursor.close()
    conn.close()

def fetch_cves(start_index=0, results_per_page=10, retries=5, delay=5):
    base_url = 'https://services.nvd.nist.gov/rest/json/cves/2.0'
    params = {
        'startIndex': start_index,
        'resultsPerPage': results_per_page
    }
    
    for attempt in range(retries):
        try:
            response = requests.get(base_url, params=params)
            if response.status_code == 200:
                data = response.json()
                print("Fetched CVEs:")
                return data
            else:
                print(f"Error fetching CVEs: {response.status_code}")
                return {}
        except requests.exceptions.RequestException as e:
            print(f"Error fetching CVEs: {e}")
        
        print(f"Retrying in {delay} seconds...")
        time.sleep(delay)
    
    print("Failed to fetch CVEs after multiple attempts.")
    return {}


# Store CVEs in the MySQL database (ensure table exists)
def store_cve(cve_data):
    conn = get_db_connection()
    cursor = conn.cursor()
    
    # Ensure table exists before insertion
    create_table()
    
    insert_query = """
        INSERT INTO cve_details (cve_id, description, published_date, modified_date, cvss_score, cvss_v2_score, year, status)
        VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
        ON DUPLICATE KEY UPDATE
        description=%s, published_date=%s, modified_date=%s, cvss_score=%s, cvss_v2_score=%s, year=%s, status=%s
    """
    
    cursor.execute(insert_query, (
        cve_data["cve_id"],
        cve_data["description"],
        cve_data["published_date"],
        cve_data["modified_date"],
        cve_data["cvss_score"],
        cve_data["cvss_v2_score"],
        cve_data["year"],
        cve_data["status"],  # Include the status in the insert
        cve_data["description"],
        cve_data["published_date"],
        cve_data["modified_date"],
        cve_data["cvss_score"],
        cve_data["cvss_v2_score"],
        cve_data["year"],
        cve_data["status"]   # Update status as well
    ))
    
    conn.commit()
    cursor.close()
    conn.close()

# Periodically fetch and store CVEs (batch mode)
# Update the sync_cves function to handle the structure of the response
def sync_cves():
    start_index = 0
    results_per_page = 10
    while True:
        print("Fetching CVEs...")
        cve_data = fetch_cves(start_index, results_per_page)

        # Ensure that 'vulnerabilities' key exists and it's not empty
        vulnerabilities = cve_data.get('vulnerabilities', [])

        if not vulnerabilities:
            print("No vulnerabilities found. Please check the response structure.")
            break

        # Loop through the list of CVE items
        for cve_item in vulnerabilities:
            cleaned_data = clean_data(cve_item)
            if cleaned_data:
                store_cve(cleaned_data)

        start_index += results_per_page
        time.sleep(10)  # Sleep for a while before the next fetch cycle

# Updated clean_data function to handle the new format of CVE data
def clean_data(cve_data):
    try:
        # Extract relevant fields from the new data format
        cve_id = cve_data.get('cve', {}).get('id')
        if not cve_id:
            # If no CVE ID is found, skip this row
            return None
        
        description = cve_data['cve'].get('descriptions', [{}])[0].get('value', "No description available")
        
        # Handle possible variations in date format
        published_date_str = cve_data['cve'].get('published', None)
        modified_date_str = cve_data['cve'].get('lastModified', None)

        if not published_date_str or not modified_date_str:
            # If published or modified dates are missing, skip this row
            return None

        try:
            published_date = datetime.strptime(published_date_str, "%Y-%m-%dT%H:%M:%S.%f")
        except ValueError:
            try:
                published_date = datetime.strptime(published_date_str, "%Y-%m-%dT%H:%M:%S")
            except ValueError:
                # If the date format is incorrect or missing, skip this row
                return None

        try:
            modified_date = datetime.strptime(modified_date_str, "%Y-%m-%dT%H:%M:%S.%f")
        except ValueError:
            try:
                modified_date = datetime.strptime(modified_date_str, "%Y-%m-%dT%H:%M:%S")
            except ValueError:
                # If the date format is incorrect or missing, skip this row
                return None
        
        # CVSS v2 score extraction
        cvss_v2_score = cve_data['cve'].get('metrics', {}).get('cvssMetricV2', [{}])[0].get('cvssData', {}).get('baseScore', None)
        
        # If CVSS score is None, set it to 0 or any placeholder value
        cvss_score = cvss_v2_score if cvss_v2_score is not None else 0.0
        
        # Extract year from the CVE ID (assuming the format is CVE-yyyy-xxxx)
        year = int(cve_id.split('-')[1])

        # Set the status (e.g., 'new' by default, or add conditions to determine status)
        status = cve_data['cve'].get('vulnStatus', "new")

        # Return cleaned data
        return {
            "cve_id": cve_id,
            "description": description,
            "published_date": published_date,
            "modified_date": modified_date,
            "cvss_score": cvss_score,
            "cvss_v2_score": cvss_v2_score,
            "year": year,
            "status": status  # Add status to the cleaned data
        }

    except Exception as e:
        # If any unexpected error occurs, return None (skip the row)
        print(f"Error processing CVE data: {e}")
        return None
# Start sync in a background thread
def start_sync_thread():
    sync_thread = threading.Thread(target=sync_cves)
    sync_thread.daemon = True
    sync_thread.start()

@app.route('/')
def home():
    return redirect(url_for('list_cves', page=1, resultsPerPage=10))

# Route to list CVEs in a table with pagination
@app.route('/cves/list', methods=['GET'])
def list_cves():
    # Pagination and Results per Page handling
    page = int(request.args.get('page', 1))
    results_per_page = int(request.args.get('resultsPerPage', 10))
    sort_order = request.args.get('sort', 'published_date')  # Default to sorting by published_date
    sort_direction = request.args.get('direction', 'ASC')  # Default to ascending order

    start_index = (page - 1) * results_per_page

    # Query to get total records count
    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)
    cursor.execute("SELECT COUNT(*) FROM cve_details")
    total_records = cursor.fetchone()['COUNT(*)']

    # Query to fetch CVEs with pagination and sorting
    cursor.execute(f"""
    SELECT cve_id, description, published_date, modified_date, cvss_v2_score, status, year
    FROM cve_details
    ORDER BY {sort_order} {sort_direction}
    LIMIT {results_per_page} OFFSET {start_index}
""")
    cves = cursor.fetchall()
    cursor.close()
    conn.close()

    return render_template('cve_list.html', cves=cves, page=page, results_per_page=results_per_page, 
                           total_records=total_records, sort_order=sort_order, sort_direction=sort_direction)

@app.route('/cves/<cve_id>', methods=['GET'])
def get_cve_by_id(cve_id):
    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)
    cursor.execute("SELECT * FROM cve_details WHERE cve_id = %s", (cve_id,))
    cve = cursor.fetchone()
    cursor.close()
    conn.close()

    if cve:
        return render_template('cve_details.html', cve=cve)
    else:
        return jsonify({"error": "CVE not found"}), 404


# API to filter CVEs by Year
@app.route('/api/cves/year/<int:year>', methods=['GET'])
def get_cves_by_year(year):
    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)
    cursor.execute("SELECT * FROM cve_details WHERE year = %s", (year,))
    cves = cursor.fetchall()
    cursor.close()
    conn.close()

    return jsonify(cves)

# API to filter CVEs by CVSS score
@app.route('/api/cves/score/<float:score>', methods=['GET'])
def get_cves_by_score(score):
    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)
    cursor.execute("SELECT * FROM cve_details WHERE cvss_score >= %s", (score,))
    cves = cursor.fetchall()
    cursor.close()
    conn.close()

    return jsonify(cves)

# API to filter CVEs modified in the last N days
@app.route('/api/cves/modified/<int:days>', methods=['GET'])
def get_cves_modified(days):
    cutoff_date = datetime.now() - timedelta(days=days)
    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)
    cursor.execute("SELECT * FROM cve_details WHERE modified_date >= %s", (cutoff_date,))
    cves = cursor.fetchall()
    cursor.close()
    conn.close()

    return jsonify(cves)

if __name__ == '__main__':
    # Ensure the table is created on startup
    create_table()
    # Start the background CVE synchronization thread
    start_sync_thread()
    app.run(debug=True)
