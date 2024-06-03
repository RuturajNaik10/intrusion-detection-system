from flask import Flask, jsonify
import random

app = Flask(__name__)

@app.route('/api/otp', methods=['GET'])
def generate_otp():
    otp = ''.join(random.choices('0123456789', k=4))
    
    response = {
        'otp': otp
    }
    
    return jsonify(response)

if __name__ == '__main__':
    app.run(debug=True,host='0.0.0.0',port=1200)
