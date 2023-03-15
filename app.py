import requests
import csv
import os
import re

from flask import Flask, request, render_template, send_file, session
from dotenv import load_dotenv

load_dotenv()

app = Flask(__name__)
app.secret_key = os.environ.get('SECRET_KEY')

API_KEY = os.environ.get('API_KEY')
VT_URL = 'https://www.virustotal.com/api/v3/'

def search_ioc(ioc):
    headers = {
        'x-apikey': API_KEY
    }
    params = {
        'include': 'analysis_results'
    }
    url = VT_URL + 'search?query=' + ioc
    response = requests.get(url, headers=headers, params=params)
    
    if response.status_code == 200:
        return response.json()
    else:
        return None

def get_reputation(ioc):
    response = search_ioc(ioc)

    if response:
        data = response['data']
        if data:
            return data[0]['attributes']
    return None

def put_value(ioc, reputation):
    ioc_info = {'ioc': ioc, 'malicious_status':'', 'vendor_flagged':'', 'type_description':'', 'md5':'', 'sha1':'', 'sha256':'', 'times_submitted':'', 'popular_threat_classification':'', 'first_submission_date':''}
    
    if reputation:
        if 'last_analysis_stats' in reputation:
            ioc_info['malicious_status'] = 'malicious' if int(reputation['last_analysis_stats']['malicious']) > 0 else 'non-malicious'
            ioc_info['vendor_flagged'] = reputation['last_analysis_stats']['malicious']

        if  re.match(r'^[a-fA-F0-9]{32,}$', ioc):
            ioc_info['type_description'] = reputation['type_description']
            ioc_info['md5'] = reputation['md5']
            ioc_info['sha1'] = reputation['sha1']
            ioc_info['sha256'] = reputation['sha256']
            ioc_info['times_submitted'] = reputation['times_submitted']
            ioc_info['popular_threat_classification'] = reputation['popular_threat_classification']['suggested_threat_label']
            ioc_info['first_submission_date'] = reputation['first_submission_date']
             
    return ioc_info

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/search', methods=['POST'])
def search():
    ioc_list = request.form['ioc_list']
    iocs = ioc_list.splitlines()

    ioc_infos = []

    for ioc in iocs:
        ioc = ioc.strip().translate({ ord(i): None for i in '[],'})
        reputation = get_reputation(ioc)
        ioc_info = put_value(ioc, reputation)
        ioc_infos.append(ioc_info)

    session['ioc_infos'] = ioc_infos

    return render_template('result.html', ioc_infos=ioc_infos)

@app.route('/download')
def download():
    ioc_infos = session.get('ioc_infos')

    if not ioc_infos:
        return 'No data available to download'

    file_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'iocs_hash.csv')

    with open(file_path, mode='w', newline='') as csvfile:
        fieldnames = ['ioc', 'malicious_status', 'vendor_flagged', 'type_description', 'md5', 'sha1', 'sha256', 'times_submitted', 'popular_threat_classification', 'first_submission_date']
        writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
        writer.writeheader()

        for ioc_info in ioc_infos:
            writer.writerow(ioc_info)

    return send_file('iocs_hash.csv', as_attachment=True)

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=8080)
