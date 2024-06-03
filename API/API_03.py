import logging
from flask import Flask, request, jsonify
from flask_cors import CORS
import csv
import json
from datetime import datetime

app = Flask(__name__)
CORS(app) 

def retrieve_data(filename, date, time):
    date = date.strip('"')
    time = time.strip('"')
    print("Inside the retrieve_data function")
    print(f"Date: {date}, Time: {time}")
    with open(filename, 'r') as file:
        reader = csv.DictReader(file)
        for row in reader:
            row_date = row['DATE']
            row_time = row['TIME-STAMP']
            if row_date == date and row_time == time:
                print("Match found!")
                return json.dumps(row, indent=4)
    print("No match found!")
    return None

@app.route('/api/get_data', methods=['GET'])
def get_data():
    filename = '/home/kali/Desktop/website/ApplicationDataManager/malicious.csv'
    date = request.args.get("date")
    time = request.args.get("time")
    print(f"Received Date: {date}, Time: {time}")
    if date and time:
        data = retrieve_data(filename, date, time)
        print(f"Data: {data}")
        if data:
            return jsonify(json.loads(data))
        else:
            return jsonify({"success": False, "message": "Data not found for the given date and time."})
    else:
        return jsonify({"success": False, "message": "Please provide both date and time."})

if __name__ == "__main__":
    app.run(debug=True, host='0.0.0.0', port=9000)
