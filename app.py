from flask import Flask, render_template, request, jsonify
import os
import sys
import threading
import time
from security_analzyer_3 import WebsiteSecurityAnalyzer

app = Flask(__name__)

# Global analyzer instance
analyzer = WebsiteSecurityAnalyzer(use_ml=True)

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/analyze', methods=['POST'])
def analyze():
    try:
        url = request.json.get('url')
        if not url:
            return jsonify({'error': 'No URL provided'}), 400
        
        # Perform the security analysis
        results = analyzer.analyze_url(url)
        
        return jsonify({
            'success': True,
            'data': results
        })
    except Exception as e:
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500

@app.route('/feedback', methods=['POST'])
def provide_feedback():
    try:
        url = request.json.get('url')
        label = request.json.get('label')  # 1 for malicious, 0 for benign
        
        if not url or label is None:
            return jsonify({'error': 'URL and label required'}), 400
        
        # Retrain the model with the feedback
        success = analyzer.retrain_model([(url, int(label))])
        
        return jsonify({
            'success': success
        })
    except Exception as e:
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500

if __name__ == '__main__':
    # Create templates directory if it doesn't exist
    os.makedirs('templates', exist_ok=True)
    
    app.run(debug=True, host='0.0.0.0', port=5000)