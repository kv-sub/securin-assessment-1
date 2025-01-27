import requests
import mysql.connector
from flask import Flask, jsonify, request, render_template, redirect, url_for
from datetime import datetime, timedelta

app = Flask(__name__)

# MySQL connection
def get_db_connection():
    return mysql.connector.connect(
        host='localhost',  # Change as necessary
        user='root',       # Change as necessary
        password='Aravind@2003',  # Change as necessary
        database='cve_database'
    )

# Fetch CVEs from NVD API
def fetch_cves(start_index=0, results_per_page=10):
    base_url = 'https://services.nvd.nist.gov/rest/json/cves/2.0'
    params = {
        'startIndex': start_index,
        'resultsPerPage': results_per_page
    }
    response = requests.get(base_url, params=params)
    return response.json()

# Clean data before storing in DB
def clean_data(cve_data):
    cve_id = cve_data['cve']['CVE_data_meta']['ID']
    description = cve_data['cve']['description']['description_data'][0]['value']
    published_date = datetime.strptime(cve_data['publishedDate'], "%Y-%m-%dT%H:%M:%S.%fZ")
    modified_date = datetime.strptime(cve_data['lastModifiedDate'], "%Y-%m-%dT%H:%M:%S.%fZ")
    cvss_score = cve_data['impact']['baseMetricV3']['cvssV3']['baseScore'] if 'baseScore' in cve_data['impact']['baseMetricV3'] else 0
    year = int(cve_id.split('-')[1])
    
    return {
        "cve_id": cve_id,
        "description": description,
        "published_date": published_date,
        "modified_date": modified_date,
        "cvss_score": cvss_score,
        "year": year
    }

# Store CVEs in the MySQL database
def store_cve(cve_data):
    conn = get_db_connection()
    cursor = conn.cursor()
    
    insert_query = """
        INSERT INTO cve_details (cve_id, description, published_date, modified_date, cvss_score, year)
        VALUES (%s, %s, %s, %s, %s, %s)
        ON DUPLICATE KEY UPDATE
        description=%s, published_date=%s, modified_date=%s, cvss_score=%s, year=%s
    """
    
    cursor.execute(insert_query, (
        cve_data["cve_id"],
        cve_data["description"],
        cve_data["published_date"],
        cve_data["modified_date"],
        cve_data["cvss_score"],
        cve_data["year"],
        cve_data["description"],
        cve_data["published_date"],
        cve_data["modified_date"],
        cve_data["cvss_score"],
        cve_data["year"]
    ))
    
    conn.commit()
    cursor.close()
    conn.close()

# Periodically fetch and store CVEs (batch mode)
def sync_cves():
    start_index = 0
    results_per_page = 10
    while True:
        cve_data = fetch_cves(start_index, results_per_page)
        if 'CVE_Items' not in cve_data:
            break
        for cve_item in cve_data['CVE_Items']:
            cleaned_data = clean_data(cve_item)
            store_cve(cleaned_data)
        start_index += results_per_page
        if len(cve_data['CVE_Items']) < results_per_page:
            break
@app.route('/')
def home():
    return redirect(url_for('list_cves', page=1, resultsPerPage=10))

# Route to list CVEs in a table with pagination
@app.route('/cves/list', methods=['GET'])
def list_cves():
    page = int(request.args.get('page', 1))
    results_per_page = int(request.args.get('resultsPerPage', 10))
    start_index = (page - 1) * results_per_page

    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)
    cursor.execute(f"SELECT * FROM cve_details LIMIT {results_per_page} OFFSET {start_index}")
    cves = cursor.fetchall()
    cursor.close()
    conn.close()

    return render_template('cve_list.html', cves=cves, page=page, results_per_page=results_per_page)

# API to get CVE details by ID
@app.route('/api/cves/<cve_id>', methods=['GET'])
def get_cve_by_id(cve_id):
    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)
    cursor.execute("SELECT * FROM cve_details WHERE cve_id = %s", (cve_id,))
    cve = cursor.fetchone()
    cursor.close()
    conn.close()

    if cve:
        return jsonify(cve)
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
    # Synchronize CVEs from NVD periodically (e.g., call sync_cves() in a background thread)
    app.run(debug=True)
