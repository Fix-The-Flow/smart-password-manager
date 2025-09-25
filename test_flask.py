#!/usr/bin/env python3
"""
Simple Flask test to verify Flask is working properly.
"""

from flask import Flask

app = Flask(__name__)

@app.route('/')
def hello():
    return """
    <h1>🎉 Flask is working!</h1>
    <p>Your Smart Password Manager Flask setup is successful.</p>
    <p><a href="/test">Test page</a></p>
    """

@app.route('/test')
def test():
    return """
    <h2>Test Page</h2>
    <p>This confirms Flask routing is working correctly.</p>
    <p><a href="/">Back to home</a></p>
    """

if __name__ == '__main__':
    print("🧪 Testing Flask setup...")
    print("Open your browser to: http://localhost:5000")
    print("Press Ctrl+C to stop")
    
    try:
        app.run(debug=True, host='0.0.0.0', port=5000)
    except Exception as e:
        print(f"Error starting Flask: {e}")
        input("Press Enter to continue...")