from flask import Flask, jsonify
import os

app = Flask(__name__)

@app.route('/')
def index():
    return """
    <h1>🚀 Email Warmup System</h1>
    <p>✅ System is running successfully!</p>
    <p>🔗 <a href="/test">Test API</a></p>
    <p>📧 Ready for email warmup campaigns</p>
    """

@app.route('/test')
def test():
    return jsonify({
        "message": "Email Warmup System is working!", 
        "status": "success",
        "version": "1.0"
    })

@app.route('/health')
def health():
    return jsonify({"status": "healthy", "service": "email-warmup"})

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 8080))
    app.run(host='0.0.0.0', port=port, debug=False)
