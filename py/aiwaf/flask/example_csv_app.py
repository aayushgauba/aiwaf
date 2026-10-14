# Example Flask app using AIWAF with CSV storage
from flask import Flask, render_template
import os
from aiwaf.flask.middleware import register_aiwaf_middlewares

app = Flask(__name__)

# CSV Storage Configuration (no database needed!)
app.config['AIWAF_USE_CSV'] = True  # Enable CSV storage
app.config['AIWAF_DATA_DIR'] = 'aiwaf_data'  # CSV files directory

# AIWAF Configuration
app.config['AIWAF_RATE_WINDOW'] = 60
app.config['AIWAF_RATE_MAX'] = 100
app.config['AIWAF_RATE_FLOOD'] = 200
app.config['AIWAF_MIN_FORM_TIME'] = 1.0

# Initialize AIWAF (will use CSV storage)
register_aiwaf_middlewares(app)

@app.route('/')
def home():
    return render_template('home.html')

@app.route('/docs')
def docs():
    return render_template('docs.html')

@app.route('/docs/<framework>')
def framework_docs(framework):
    return render_template(f'docs_{framework}.html')

@app.route('/docs/<framework>/<page>')
def doc_page(framework, page):
    return render_template(f'docs_{framework}_{page}.html')

# Admin routes for managing CSV data
@app.route('/admin/allowlist/<ip>')
def allowlist_ip(ip):
    from aiwaf.flask.storage import add_ip_allowlist
    add_ip_allowlist(ip)
    return f"IP {ip} added to allowlist (saved to CSV)"

@app.route('/admin/blocklist/<ip>')
def blocklist_ip(ip):
    from aiwaf.flask.storage import add_ip_blocklist
    add_ip_blocklist(ip, "Admin blocked")
    return f"IP {ip} added to blocklist (saved to CSV)"

@app.route('/admin/block-keyword/<keyword>')
def block_keyword(keyword):
    from aiwaf.flask.storage import add_keyword
    add_keyword(keyword)
    return f"Keyword '{keyword}' blocked (saved to CSV)"

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5000))
    app.run(host='0.0.0.0', port=port, debug=False)

# Compatibility aliases for callers using the previous terminology.
whitelist_ip = allowlist_ip
blacklist_ip = blocklist_ip
