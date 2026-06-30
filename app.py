import os
import sys
import json
import urllib.parse
import hashlib
import requests
import urllib3
from flask import Flask, request, jsonify, render_template_string

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

app = Flask(__name__)

# Core Garena API callback processor
def fetch_player_info(access_token):
    try:
        player_url = f"https://api-otrss.garena.com/support/callback/?access_token={access_token}"
        headers = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/115.0.0.0 Safari/537.36"
        }
        p_res = requests.get(player_url, headers=headers, timeout=10, allow_redirects=True)
        parsed_url = urllib.parse.urlparse(p_res.url)
        query_params = urllib.parse.parse_qs(parsed_url.query)
        
        return {
            "uid": query_params.get("account_id", ["Unknown"])[0],
            "nickname": urllib.parse.unquote(query_params.get("nickname", ["Unknown"])[0]),
            "region": query_params.get("region", ["Unknown"])[0]
        }
    except Exception as e:
        return {
            "uid": "Unknown",
            "nickname": "Unknown", 
            "region": "Unknown",
            "error": str(e)
        }

# --- Backend Flask API Handlers ---

@app.route('/api/check_bind', methods=['POST'])
def api_check_bind():
    data = request.get_json() or {}
    access_token = data.get('access_token', '').strip()
    if not access_token:
        return jsonify({"success": False, "error": "Access Token is required."}), 400
        
    player = fetch_player_info(access_token)
    
    url = "https://100067.connect.garena.com/game/account_security/bind:get_bind_info"
    payload = {'app_id': "100067", 'access_token': access_token}
    headers = {
        'User-Agent': "GarenaMSDK/4.0.19P9(Redmi Note 5 ;Android 9;en;US;)",
        'Connection': "Keep-Alive"
    }
    
    try:
        response = requests.get(url, params=payload, headers=headers, timeout=10)
        if response.status_code == 200:
            return jsonify({
                "success": True,
                "player": player,
                "bind": response.json()
            })
        else:
            return jsonify({"success": False, "error": f"API Rejection: {response.status_code}"}), 400
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500

@app.route('/api/send_otp', methods=['POST'])
def api_send_otp():
    data = request.get_json() or {}
    email = data.get('email', '').strip()
    access_token = data.get('access_token', '').strip()
    
    if not email or not access_token:
        return jsonify({"success": False, "error": "Parameters missing."}), 400
        
    headers = {
        "User-Agent": "GarenaMSDK/4.0.30",
        "Content-Type": "application/x-www-form-urlencoded",
        "Accept": "application/json"
    }
    send_otp_url = "https://100067.connect.garena.com/game/account_security/bind:send_otp"
    send_otp_data = {
        "email": email,
        "locale": "en_PK",
        "region": "PK",
        "app_id": "100067",
        "access_token": access_token
    }
    try:
        resp = requests.post(send_otp_url, headers=headers, data=send_otp_data, timeout=10)
        return jsonify({"success": True, "data": resp.json()})
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500

@app.route('/api/verify_otp', methods=['POST'])
def api_verify_otp():
    data = request.get_json() or {}
    email = data.get('email', '').strip()
    access_token = data.get('access_token', '').strip()
    otp = data.get('otp', '').strip()
    
    if not email or not access_token or not otp:
        return jsonify({"success": False, "error": "Required fields missing."}), 400
        
    headers = {
        "User-Agent": "GarenaMSDK/4.0.30",
        "Content-Type": "application/x-www-form-urlencoded",
        "Accept": "application/json"
    }
    verify_url = "https://100067.connect.garena.com/game/account_security/bind:verify_otp"
    verify_data = {
        "app_id": "100067",
        "access_token": access_token,
        "email": email,
        "code": otp,
        "otp": otp,
        "type": "1"
    }
    try:
        resp = requests.post(verify_url, headers=headers, data=verify_data, timeout=10)
        res_json = resp.json()
        verifier_token = res_json.get("verifier_token", "")
        return jsonify({
            "success": True,
            "verifier_token": verifier_token,
            "data": res_json
        })
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500

@app.route('/api/create_bind', methods=['POST'])
def api_create_bind():
    data = request.get_json() or {}
    email = data.get('email', '').strip()
    access_token = data.get('access_token', '').strip()
    verifier_token = data.get('verifier_token', '').strip()
    security_code = data.get('security_code', '').strip()
    
    if not all([email, access_token, verifier_token, security_code]):
        return jsonify({"success": False, "error": "Setup variables incomplete."}), 400
        
    headers = {
        "User-Agent": "GarenaMSDK/4.0.30",
        "Content-Type": "application/x-www-form-urlencoded",
        "Accept": "application/json"
    }
    bind_url = "https://100067.connect.garena.com/game/account_security/bind:create_bind_request"
    bind_data = {
        "email": email,
        "app_id": "100067",
        "access_token": access_token,
        "verifier_token": verifier_token,
        "secondary_password": security_code
    }
    try:
        resp = requests.post(bind_url, headers=headers, data=bind_data, timeout=10)
        return jsonify({"success": True, "data": resp.json()})
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500

@app.route('/api/verify_identity', methods=['POST'])
def api_verify_identity():
    data = request.get_json() or {}
    email = data.get('email', '').strip()
    access_token = data.get('access_token', '').strip()
    otp = data.get('otp', '').strip()
    security_code = data.get('secondary_password', '').strip()
    
    if not email or not access_token:
        return jsonify({"success": False, "error": "Incomplete request profile details."}), 400
        
    headers = {
        "User-Agent": "GarenaMSDK/4.0.30",
        "Content-Type": "application/x-www-form-urlencoded",
        "Accept": "application/json"
    }
    verify_url = "https://100067.connect.garena.com/game/account_security/bind:verify_identity"
    verify_data = {
        "email": email,
        "app_id": "100067",
        "access_token": access_token
    }
    if otp:
        verify_data["otp"] = otp
    elif security_code:
        hashed = hashlib.sha256(security_code.encode('utf-8')).hexdigest()
        verify_data["secondary_password"] = hashed
    else:
        return jsonify({"success": False, "error": "Identity code or OTP parameter missing."}), 400
        
    try:
        resp = requests.post(verify_url, headers=headers, data=verify_data, timeout=10)
        res_json = resp.json()
        identity_token = res_json.get("identity_token", "")
        return jsonify({
            "success": True,
            "identity_token": identity_token,
            "data": res_json
        })
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500

@app.route('/api/create_rebind', methods=['POST'])
def api_create_rebind():
    data = request.get_json() or {}
    identity_token = data.get('identity_token', '').strip()
    email = data.get('email', '').strip()
    verifier_token = data.get('verifier_token', '').strip()
    access_token = data.get('access_token', '').strip()
    
    if not all([identity_token, email, verifier_token, access_token]):
        return jsonify({"success": False, "error": "Missing parameters."}), 400
        
    headers = {
        "User-Agent": "GarenaMSDK/4.0.30",
        "Content-Type": "application/x-www-form-urlencoded",
        "Accept": "application/json"
    }
    url_rebind = "https://100067.connect.garena.com/game/account_security/bind:create_rebind_request"
    rebind_data = {
        "identity_token": identity_token,
        "email": email,
        "app_id": "100067",
        "verifier_token": verifier_token,
        "access_token": access_token
    }
    try:
        resp = requests.post(url_rebind, headers=headers, data=rebind_data, timeout=10)
        return jsonify({"success": True, "data": resp.json()})
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500

@app.route('/api/create_unbind', methods=['POST'])
def api_create_unbind():
    data = request.get_json() or {}
    identity_token = data.get('identity_token', '').strip()
    access_token = data.get('access_token', '').strip()
    
    if not identity_token or not access_token:
        return jsonify({"success": False, "error": "Missing identity key metrics."}), 400
        
    headers = {
        "User-Agent": "GarenaMSDK/4.0.30",
        "Content-Type": "application/x-www-form-urlencoded",
        "Accept": "application/json"
    }
    unbind_url = "https://100067.connect.garena.com/game/account_security/bind:create_unbind_request"
    unbind_data = {
        "app_id": "100067",
        "access_token": access_token,
        "identity_token": identity_token
    }
    try:
        resp = requests.post(unbind_url, headers=headers, data=unbind_data, timeout=10)
        return jsonify({"success": True, "data": resp.json()})
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500

@app.route('/api/cancel_bind', methods=['POST'])
def api_cancel_bind():
    data = request.get_json() or {}
    access_token = data.get('access_token', '').strip()
    
    if not access_token:
        return jsonify({"success": False, "error": "Authentication token missing."}), 400
        
    url = "https://100067.connect.garena.com/game/account_security/bind:cancel_request"
    headers = {
        "User-Agent": "GarenaMSDK/4.0.30",
        "Content-Type": "application/x-www-form-urlencoded",
        "Accept": "application/json"
    }
    bind_data = {"app_id": "100067", "access_token": access_token}
    try:
        resp = requests.post(url, headers=headers, data=bind_data, timeout=10)
        return jsonify({"success": True, "data": resp.json()})
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500

@app.route('/api/eat_to_token', methods=['POST'])
def api_eat_to_token():
    data = request.get_json() or {}
    eat_input = data.get('eat_input', '').strip()
    
    if not eat_input:
        return jsonify({"success": False, "error": "Missing key or link string."}), 400
        
    eat_token = eat_input
    if "http" in eat_input or "?" in eat_input:
        try:
            parsed_url = urllib.parse.urlparse(eat_input)
            query_params = urllib.parse.parse_qs(parsed_url.query)
            if 'eat' in query_params:
                eat_token = query_params['eat'][0]
        except Exception as e:
            return jsonify({"success": False, "error": f"Error parsing URL string: {str(e)}"}), 400
            
    api_url = f"https://api-otrss.garena.com/support/callback/?access_token={eat_token}"
    headers = {
        "User-Agent": "Mozilla/5.0 (Linux; Android 13; Mobile) AppleWebKit/537.36"
    }
    try:
        response = requests.get(api_url, headers=headers, allow_redirects=True, timeout=12)
        parsed_final = urllib.parse.urlparse(response.url)
        final_params = urllib.parse.parse_qs(parsed_final.query)
        
        if 'access_token' in final_params:
            return jsonify({
                "success": True,
                "access_token": final_params['access_token'][0],
                "account_id": final_params.get('account_id', ['Unknown'])[0],
                "nickname": urllib.parse.unquote(final_params.get('nickname', ['Unknown'])[0]),
                "region": final_params.get('region', ['Unknown'])[0]
            })
        else:
            return jsonify({"success": False, "error": "Target EAT key validation expired."}), 400
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500

@app.route('/api/revoke_token', methods=['POST'])
def api_revoke_token():
    data = request.get_json() or {}
    access_token = data.get('access_token', '').strip()
    
    if not access_token:
        return jsonify({"success": False, "error": "Access Token missing."}), 400
        
    player = fetch_player_info(access_token)
    if player.get("uid") == "Unknown":
        return jsonify({"success": False, "error": "Authentication key expired or invalid."}), 400
        
    refresh_token = "1380dcb63ab3a077dc05bdf0b25ba4497c403a5b4eae96d7203010eafa6c83a8"
    logout_url = f"https://100067.connect.garena.com/oauth/logout?access_token={access_token}&refresh_token={refresh_token}"
    headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
    }
    try:
        logout_res = requests.get(logout_url, headers=headers, timeout=12)
        if logout_res.status_code == 200 and "error" not in logout_res.text:
            return jsonify({
                "success": True,
                "player": player,
                "message": "Token revoked."
            })
        else:
            return jsonify({"success": False, "error": "Logout action rejected by API endpoint."}), 400
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500


# --- Frontend Blueprint Assembly ---

HTML_TEMPLATE = """<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0, maximum-scale=1.0, user-scalable=no">
    <title>CKR BIND TOOL</title>
    
    <!-- CDNs -->
    <link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/bootstrap-icons@1.11.1/font/bootstrap-icons.css">
    <link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700;800&display=swap" rel="stylesheet">
    
    <style>
        :root {
            --bg-base: #0f172a;
            --bg-card: #1e293b;
            --bg-input: #0f172a;
            --primary: #2563eb;
            --primary-hover: #1d4ed8;
            --success: #22c55e;
            --danger: #ef4444;
            --warning: #f59e0b;
            --text-main: #ffffff;
            --text-muted: #94a3b8;
            --radius-btn: 20px;
            --radius-card: 12px;
            --shadow-soft: 0 10px 20px -10px rgba(0, 0, 0, 0.5);
            --transition: all 0.25s cubic-bezier(0.4, 0, 0.2, 1);
        }

        * {
            box-sizing: border-box;
            margin: 0;
            padding: 0;
            font-family: 'Inter', sans-serif;
            -webkit-tap-highlight-color: transparent;
        }

        body {
            background-color: var(--bg-base);
            color: var(--text-main);
            min-height: 100vh;
            display: flex;
            align-items: center;
            justify-content: center;
            font-size: 0.8rem;
            line-height: 1.4;
            overflow-x: hidden;
        }

        /* --- Transitions --- */
        .screen {
            display: none;
            width: 100%;
            opacity: 0;
        }

        .screen.active {
            display: flex;
            opacity: 1;
        }

        /* Forward navigation: slide up and fade */
        .slide-up-in {
            animation: slideUpIn 0.25s cubic-bezier(0.16, 1, 0.3, 1) forwards;
        }

        /* Backward navigation: slide from left (rightwards transition) and fade */
        .slide-right-in {
            animation: slideRightIn 0.25s cubic-bezier(0.16, 1, 0.3, 1) forwards;
        }

        @keyframes slideUpIn {
            from { opacity: 0; transform: translateY(12px); }
            to { opacity: 1; transform: translateY(0); }
        }

        @keyframes slideRightIn {
            from { opacity: 0; transform: translateX(-12px); }
            to { opacity: 1; transform: translateX(0); }
        }

        @keyframes shake {
            0%, 100% { transform: translateX(0); }
            20%, 60% { transform: translateX(-8px); }
            40%, 80% { transform: translateX(8px); }
        }

        .shake-it { animation: shake 0.35s ease-in-out; }

        /* --- Login Screen --- */
        #login-screen {
            flex-direction: column;
            align-items: center;
            max-width: 320px;
            padding: 1.5rem;
        }

        .login-card {
            background-color: var(--bg-card);
            border-radius: var(--radius-card);
            padding: 1.5rem;
            width: 100%;
            box-shadow: var(--shadow-soft);
            text-align: center;
        }

        .login-icon-box {
            width: 48px;
            height: 48px;
            background-color: rgba(37, 99, 235, 0.1);
            border-radius: 50%;
            display: flex;
            align-items: center;
            justify-content: center;
            margin: 0 auto 1rem auto;
            color: var(--primary);
            font-size: 1.4rem;
        }

        .login-card h2 {
            font-size: 1.1rem;
            font-weight: 800;
            margin-bottom: 0.25rem;
            letter-spacing: 0.02em;
        }

        .login-card p {
            font-size: 0.75rem;
            color: var(--text-muted);
            margin-bottom: 1.25rem;
        }

        /* --- Dashboard Screen --- */
        #dashboard-screen {
            max-width: 800px;
            padding: 1rem;
            min-height: 100vh;
            flex-direction: column;
            align-self: flex-start;
        }

        header {
            display: flex;
            align-items: center;
            justify-content: space-between;
            padding: 0.5rem 0.25rem;
            margin-bottom: 1rem;
            border-bottom: 1px solid rgba(255, 255, 255, 0.03);
        }

        .header-left {
            display: flex;
            align-items: center;
            gap: 0.5rem;
        }

        .header-logo {
            width: 32px;
            height: 32px;
            background-color: rgba(37, 99, 235, 0.1);
            border-radius: 8px;
            display: flex;
            align-items: center;
            justify-content: center;
            color: var(--primary);
            font-size: 1rem;
        }

        .header-text h1 {
            font-size: 0.95rem;
            font-weight: 800;
            letter-spacing: 0.03em;
            color: #ffffff;
        }

        .header-text span {
            font-size: 0.65rem;
            color: var(--text-muted);
            font-weight: 500;
            display: block;
        }

        .logout-btn {
            background: none;
            border: none;
            color: var(--text-muted);
            cursor: pointer;
            font-size: 1.1rem;
            padding: 0.25rem;
            transition: var(--transition);
        }

        .logout-btn:hover {
            color: var(--danger);
        }

        /* --- Menu Grid Cards --- */
        .menu-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(220px, 1fr));
            gap: 0.75rem;
            margin-bottom: 1rem;
        }

        .menu-card {
            background-color: var(--bg-card);
            border-radius: var(--radius-card);
            padding: 1rem;
            cursor: pointer;
            display: flex;
            align-items: flex-start;
            gap: 0.75rem;
            box-shadow: var(--shadow-soft);
            transition: var(--transition);
            position: relative;
            overflow: hidden;
            text-align: left;
        }

        .menu-card:hover {
            transform: translateY(-2px);
            background-color: rgba(255, 255, 255, 0.03);
        }

        .menu-card:active {
            transform: scale(0.98);
        }

        .menu-card-icon {
            width: 32px;
            height: 32px;
            border-radius: 8px;
            background-color: rgba(37, 99, 235, 0.08);
            color: var(--primary);
            display: flex;
            align-items: center;
            justify-content: center;
            font-size: 1.1rem;
            flex-shrink: 0;
        }

        .menu-card-body h3 {
            font-size: 0.8rem;
            font-weight: 700;
            margin-bottom: 0.15rem;
        }

        .menu-card-body p {
            font-size: 0.68rem;
            color: var(--text-muted);
            line-height: 1.2;
        }

        /* --- Tool Interface Panels --- */
        .tool-panel {
            display: none;
            background-color: var(--bg-card);
            border-radius: var(--radius-card);
            padding: 1.25rem;
            box-shadow: var(--shadow-soft);
            width: 100%;
        }

        .tool-panel-header {
            display: flex;
            align-items: center;
            gap: 0.5rem;
            margin-bottom: 1.25rem;
            border-bottom: 1px solid rgba(255, 255, 255, 0.03);
            padding-bottom: 0.5rem;
        }

        .btn-back {
            background: none;
            border: none;
            color: var(--text-muted);
            cursor: pointer;
            font-size: 0.75rem;
            font-weight: 700;
            display: flex;
            align-items: center;
            gap: 0.25rem;
            transition: var(--transition);
            text-transform: uppercase;
        }

        .btn-back:hover {
            color: #ffffff;
        }

        .tool-panel-title {
            font-size: 0.9rem;
            font-weight: 700;
            display: flex;
            align-items: center;
            gap: 0.4rem;
        }

        .tool-panel-title i {
            color: var(--primary);
        }

        /* --- Progress indicators --- */
        .flow-tracker {
            display: flex;
            align-items: center;
            justify-content: space-between;
            margin: 0.5rem auto 1.25rem auto;
            max-width: 240px;
            position: relative;
        }

        .flow-tracker::before {
            content: '';
            position: absolute;
            top: 50%;
            left: 0;
            right: 0;
            height: 2px;
            background-color: var(--bg-base);
            z-index: 1;
            transform: translateY(-50%);
        }

        .flow-node {
            width: 24px;
            height: 24px;
            border-radius: 50%;
            background-color: var(--bg-base);
            color: var(--text-muted);
            z-index: 2;
            display: flex;
            align-items: center;
            justify-content: center;
            font-size: 0.7rem;
            font-weight: 700;
            transition: var(--transition);
        }

        .flow-node.active {
            background-color: var(--primary);
            color: #ffffff;
        }

        .flow-node.completed {
            background-color: var(--success);
            color: #ffffff;
        }

        /* --- Forms / Inputs --- */
        .form-item {
            position: relative;
            margin-bottom: 0.75rem;
            width: 100%;
        }

        .form-input {
            width: 100%;
            height: 38px;
            background-color: var(--bg-input);
            border: none;
            border-radius: 8px;
            padding: 14px 2.5rem 0 0.75rem;
            color: var(--text-main);
            font-size: 0.75rem;
            font-weight: 500;
            outline: none;
            transition: var(--transition);
        }

        .form-input:focus {
            box-shadow: 0 0 0 1px var(--primary);
        }

        .form-item label {
            position: absolute;
            left: 0.75rem;
            top: 50%;
            transform: translateY(-50%);
            font-size: 0.75rem;
            color: var(--text-muted);
            pointer-events: none;
            transition: var(--transition);
        }

        .form-input:focus ~ label,
        .form-input:not(:placeholder-shown) ~ label {
            top: 10px;
            font-size: 0.6rem;
            font-weight: 700;
            color: var(--primary);
        }

        .input-addon-btn {
            position: absolute;
            right: 0.75rem;
            top: 50%;
            transform: translateY(-50%);
            background: none;
            border: none;
            color: var(--text-muted);
            cursor: pointer;
            font-size: 0.95rem;
            display: flex;
            align-items: center;
            z-index: 5;
        }

        .input-addon-btn:hover {
            color: #ffffff;
        }

        .toggle-row {
            display: flex;
            background-color: var(--bg-input);
            border-radius: 8px;
            padding: 2px;
            gap: 2px;
            margin-bottom: 0.75rem;
        }

        .toggle-btn {
            flex: 1;
            border: none;
            background: none;
            color: var(--text-muted);
            font-size: 0.75rem;
            font-weight: 600;
            padding: 0.4rem;
            cursor: pointer;
            border-radius: 6px;
            transition: var(--transition);
        }

        .toggle-btn.active {
            background-color: var(--bg-card);
            color: #ffffff;
        }

        /* --- Buttons --- */
        .btn {
            background-color: var(--primary);
            color: #ffffff;
            border: none;
            border-radius: var(--radius-btn);
            padding: 0.55rem 1.25rem;
            font-size: 0.75rem;
            font-weight: 700;
            cursor: pointer;
            display: inline-flex;
            align-items: center;
            justify-content: center;
            gap: 0.4rem;
            transition: var(--transition);
            letter-spacing: 0.02em;
        }

        .btn:hover {
            background-color: var(--primary-hover);
        }

        .btn:disabled {
            opacity: 0.6;
            cursor: not-allowed;
        }

        .btn-sec {
            background-color: rgba(255, 255, 255, 0.05);
            color: #ffffff;
        }

        .btn-sec:hover {
            background-color: rgba(255, 255, 255, 0.1);
        }

        .btn-danger {
            background-color: var(--danger);
        }

        .btn-danger:hover {
            background-color: #dc2626;
        }

        .btn-full {
            width: 100%;
        }

        .flex-btn-row {
            display: flex;
            gap: 0.5rem;
            margin-top: 1rem;
        }

        /* --- Metadata Visualizers --- */
        .res-container {
            margin-top: 1rem;
            background-color: rgba(255, 255, 255, 0.01);
            border-radius: 8px;
            padding: 0.75rem;
        }

        .res-title {
            font-size: 0.65rem;
            font-weight: 800;
            color: var(--primary);
            text-transform: uppercase;
            letter-spacing: 0.04em;
            margin-bottom: 0.5rem;
        }

        .grid-2col {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(140px, 1fr));
            gap: 0.5rem;
        }

        .res-item {
            display: flex;
            flex-direction: column;
            background-color: var(--bg-input);
            padding: 0.4rem 0.6rem;
            border-radius: 6px;
        }

        .res-lbl {
            font-size: 0.6rem;
            color: var(--text-muted);
            font-weight: 600;
            text-transform: uppercase;
        }

        .res-val-wrapper {
            display: flex;
            align-items: center;
            justify-content: space-between;
            gap: 0.25rem;
        }

        .res-val {
            font-size: 0.75rem;
            font-weight: 700;
            color: #ffffff;
            word-break: break-all;
        }

        .btn-copy-micro {
            background: none;
            border: none;
            color: var(--primary);
            cursor: pointer;
            padding: 0.1rem;
            font-size: 0.75rem;
        }

        /* --- Modals --- */
        .modal-overlay {
            position: fixed;
            inset: 0;
            background-color: rgba(15, 23, 42, 0.75);
            backdrop-filter: blur(6px);
            -webkit-backdrop-filter: blur(6px);
            z-index: 1000;
            display: flex;
            align-items: center;
            justify-content: center;
            opacity: 0;
            pointer-events: none;
            transition: opacity 0.2s ease;
            padding: 1rem;
        }

        .modal-overlay.active {
            opacity: 1;
            pointer-events: auto;
        }

        .modal-card {
            background-color: var(--bg-card);
            border-radius: var(--radius-card);
            max-width: 340px;
            width: 100%;
            padding: 1.25rem;
            box-shadow: var(--shadow-soft);
            text-align: center;
            transform: scale(0.96);
            transition: transform 0.2s cubic-bezier(0.34, 1.56, 0.64, 1);
        }

        .modal-overlay.active .modal-card {
            transform: scale(1);
        }

        .modal-icon-box {
            width: 42px;
            height: 42px;
            border-radius: 50%;
            display: flex;
            align-items: center;
            justify-content: center;
            margin: 0 auto 0.75rem auto;
            font-size: 1.3rem;
        }

        .modal-icon-box.warn { background-color: rgba(245, 158, 11, 0.1); color: var(--warning); }
        .modal-icon-box.error { background-color: rgba(239, 68, 68, 0.1); color: var(--danger); }
        .modal-icon-box.success { background-color: rgba(34, 197, 94, 0.1); color: var(--success); }

        .modal-card h3 {
            font-size: 0.9rem;
            font-weight: 800;
            margin-bottom: 0.4rem;
        }

        .modal-card p {
            font-size: 0.75rem;
            color: var(--text-muted);
            margin-bottom: 1rem;
            line-height: 1.3;
        }

        /* --- Toasts --- */
        #toast-shelf {
            position: fixed;
            bottom: 16px;
            right: 16px;
            z-index: 1100;
            display: flex;
            flex-direction: column;
            gap: 8px;
            max-width: 280px;
            width: 100%;
        }

        .toast-entity {
            background-color: var(--bg-card);
            padding: 0.6rem 0.85rem;
            border-radius: 8px;
            box-shadow: var(--shadow-soft);
            display: flex;
            align-items: center;
            gap: 0.5rem;
            font-size: 0.72rem;
            font-weight: 600;
            color: #ffffff;
            opacity: 0;
            transform: translateY(12px);
            transition: all 0.25s cubic-bezier(0.16, 1, 0.3, 1);
        }

        .toast-entity.show {
            opacity: 1;
            transform: translateY(0);
        }

        .toast-entity.success { border-left: 2px solid var(--success); }
        .toast-entity.error { border-left: 2px solid var(--danger); }
        .toast-entity.info { border-left: 2px solid var(--primary); }
        .toast-entity.warning { border-left: 2px solid var(--warning); }

        .toast-entity i { font-size: 0.95rem; }
        .toast-entity.success i { color: var(--success); }
        .toast-entity.error i { color: var(--danger); }
        .toast-entity.info i { color: var(--primary); }
        .toast-entity.warning i { color: var(--warning); }

        /* --- Loading Overlay --- */
        #loading-overlay {
            position: fixed;
            inset: 0;
            background-color: rgba(15, 23, 42, 0.6);
            backdrop-filter: blur(4px);
            -webkit-backdrop-filter: blur(4px);
            z-index: 2000;
            display: flex;
            align-items: center;
            justify-content: center;
            opacity: 0;
            pointer-events: none;
            transition: opacity 0.2s ease;
        }

        #loading-overlay.active {
            opacity: 1;
            pointer-events: auto;
        }

        .mini-spinner {
            width: 28px;
            height: 28px;
            border: 2px solid rgba(255, 255, 255, 0.1);
            border-radius: 50%;
            border-top-color: var(--primary);
            animation: spin 0.6s linear infinite;
        }

        @keyframes spin {
            to { transform: rotate(360deg); }
        }

        @media (max-width: 480px) {
            .menu-grid {
                grid-template-columns: 1fr;
            }
        }
    </style>
</head>
<body>

    <!-- ================== AUTHENTICATION VIEWS ================== -->
    <div id="login-screen" class="screen">
        <div class="login-card" id="login-card-anim">
            <div class="login-icon-box">
                <i class="bi bi-shield-lock"></i>
            </div>
            <h2>FF TOOL</h2>
            <p> </p>
            
            <div class="form-item">
                <input type="password" class="form-input" id="portal-pwd" placeholder=" " onkeydown="if(event.key==='Enter') executeLogin()">
                <label> </label>
                <button class="input-addon-btn" onclick="togglePassVisibility('portal-pwd')">
                    <i class="bi bi-eye" id="portal-pwd-eye"></i>
                </button>
            </div>
            
            <button class="btn btn-full" onclick="executeLogin()">ENTER</button>
        </div>
    </div>

    <!-- ================== SYSTEM DASHBOARD ================== -->
    <div id="dashboard-screen" class="screen">
        
        <!-- Sticky Header Context -->
        <header>
            <div class="header-left">
                <div class="header-logo">
                    <i class="bi bi-cpu-fill"></i>
                </div>
                <div class="header-text">
                    <h1>CKRPRO</h1>
                    <span>FREE FIRE BIND UNBIND TOOL</span>
                </div>
            </div>
            <button class="logout-btn" onclick="promptLogout()" title="Lock Session">
                <i class="bi bi-power"></i>
            </button>
        </header>

        <!-- Viewport Workspace Router -->
        <main>
            
            <!-- Default Grid Navigation Map -->
            <div class="menu-grid" id="main-menu-grid">
                
                <div class="menu-card" onclick="routeToTool('tool-check-bind')">
                    <div class="menu-card-icon"><i class="bi bi-person-check-fill"></i></div>
                    <div class="menu-card-body">
                        <h3>Check Bind Info</h3>
                        <p>Query binding metrics & region mappings.</p>
                    </div>
                </div>

                <div class="menu-card" onclick="routeToTool('tool-bind-email', 1)">
                    <div class="menu-card-icon"><i class="bi bi-envelope-plus-fill"></i></div>
                    <div class="menu-card-body">
                        <h3>Bind Email</h3>
                        <p>Bind new verification email routes.</p>
                    </div>
                </div>

                <div class="menu-card" onclick="routeToTool('tool-unbind-email', 1)">
                    <div class="menu-card-icon"><i class="bi bi-envelope-x-fill"></i></div>
                    <div class="menu-card-body">
                        <h3>Unbind Email</h3>
                        <p>Deregister configured verification mails.</p>
                    </div>
                </div>

                <div class="menu-card" onclick="routeToTool('tool-change-bind', 1)">
                    <div class="menu-card-icon"><i class="bi bi-arrow-repeat"></i></div>
                    <div class="menu-card-body">
                        <h3>Change Bind Email</h3>
                        <p>Migrate active verification email setups.</p>
                    </div>
                </div>

                <div class="menu-card" onclick="routeToTool('tool-cancel-bind')">
                    <div class="menu-card-icon"><i class="bi bi-x-circle-fill"></i></div>
                    <div class="menu-card-body">
                        <h3>Cancel Bind Request</h3>
                        <p>Abort pending bind countdown schedules.</p>
                    </div>
                </div>

                <div class="menu-card" onclick="routeToTool('tool-eat-token')">
                    <div class="menu-card-icon"><i class="bi bi-key-fill"></i></div>
                    <div class="menu-card-body">
                        <h3>EAT → Access Token</h3>
                        <p>Exchange security EAT links for keys.</p>
                    </div>
                </div>

                <div class="menu-card" onclick="routeToTool('tool-revoke-token')">
                    <div class="menu-card-icon"><i class="bi bi-shield-lock-fill"></i></div>
                    <div class="menu-card-body">
                        <h3>Revoke Access Token</h3>
                        <p>Instantly terminate active credential slots.</p>
                    </div>
                </div>

            </div>

            <!-- Panel 1: Check Bind Info -->
            <div class="tool-panel" id="tool-check-bind">
                <div class="tool-panel-header">
                    <button class="btn-back" onclick="triggerBack()"><i class="bi bi-arrow-left"></i> Back</button>
                    <div class="tool-panel-title"><i class="bi bi-person-check-fill"></i> Check Bind Info</div>
                </div>
                <div class="form-item">
                    <input type="text" class="form-input" id="chk-token" placeholder=" ">
                    <label>Access Token</label>
                </div>
                <button class="btn btn-full" onclick="executeCheckBind()">Execute Query</button>

                <div class="res-container" id="chk-res" style="display: none;">
                    <div class="res-title">Account Metadata</div>
                    <div class="grid-2col">
                        <div class="res-item">
                            <span class="res-lbl">UID</span>
                            <div class="res-val-wrapper">
                                <span class="res-val" id="val-uid">-</span>
                                <button class="btn-copy-micro" onclick="copyValue('val-uid')"><i class="bi bi-copy"></i></button>
                            </div>
                        </div>
                        <div class="res-item">
                            <span class="res-lbl">Nickname</span>
                            <span class="res-val" id="val-nick">-</span>
                        </div>
                        <div class="res-item">
                            <span class="res-lbl">Region</span>
                            <span class="res-val" id="val-reg">-</span>
                        </div>
                    </div>
                    <div class="res-title" style="margin-top: 0.75rem;">Bind Data</div>
                    <div class="grid-2col">
                        <div class="res-item">
                            <span class="res-lbl">Current Email</span>
                            <div class="res-val-wrapper">
                                <span class="res-val" id="val-email">-</span>
                                <button class="btn-copy-micro" onclick="copyValue('val-email')"><i class="bi bi-copy"></i></button>
                            </div>
                        </div>
                        <div class="res-item">
                            <span class="res-lbl">Pending Email</span>
                            <div class="res-val-wrapper">
                                <span class="res-val" id="val-pending">-</span>
                                <button class="btn-copy-micro" onclick="copyValue('val-pending')"><i class="bi bi-copy"></i></button>
                            </div>
                        </div>
                        <div class="res-item">
                            <span class="res-lbl">Countdown</span>
                            <span class="res-val" id="val-time">-</span>
                        </div>
                        <div class="res-item">
                            <span class="res-lbl">Status Code</span>
                            <span class="res-val" id="val-status">-</span>
                        </div>
                    </div>
                </div>
            </div>

            <!-- Panel 2: Bind Email -->
            <div class="tool-panel" id="tool-bind-email">
                <div class="tool-panel-header">
                    <button class="btn-back" onclick="triggerBack()"><i class="bi bi-arrow-left"></i> Back</button>
                    <div class="tool-panel-title"><i class="bi bi-envelope-plus-fill"></i> Bind Email</div>
                </div>
                <div class="flow-tracker">
                    <div class="flow-node active" id="node-bind-1">1</div>
                    <div class="flow-node" id="node-bind-2">2</div>
                    <div class="flow-node" id="node-bind-3">3</div>
                </div>
                
                <div id="bind-step1-wrapper">
                    <div class="form-item">
                        <input type="text" class="form-input" id="bind-token-in" placeholder=" ">
                        <label>Access Token</label>
                    </div>
                    <div class="form-item">
                        <input type="email" class="form-input" id="bind-mail-in" placeholder=" ">
                        <label>Email Address</label>
                    </div>
                </div>
                
                <div id="bind-step2-wrapper" style="display: none;">
                    <div class="form-item">
                        <input type="text" class="form-input" id="bind-otp-in" placeholder=" ">
                        <label>OTP Code</label>
                    </div>
                </div>
                
                <div id="bind-step3-wrapper" style="display: none;">
                    <div class="form-item">
                        <input type="password" class="form-input" id="bind-pin-in" placeholder=" " maxlength="6" inputmode="numeric">
                        <label>6-Digit Security PIN</label>
                    </div>
                </div>

                <div class="flex-btn-row">
                    <button class="btn btn-full" id="btn-bind-otp" onclick="bindEmailSendOTP()">Send OTP</button>
                    <button class="btn btn-full" id="btn-bind-verify" onclick="bindEmailVerifyOTP()" style="display: none;">Verify OTP</button>
                    <button class="btn btn-full" id="btn-bind-apply" onclick="bindEmailComplete()" style="display: none;">Complete Bind</button>
                    <button class="btn btn-sec" id="btn-bind-reset" onclick="resetBindFlow()" style="display: none;">Reset</button>
                </div>
            </div>

            <!-- Panel 3: Unbind Email -->
            <div class="tool-panel" id="tool-unbind-email">
                <div class="tool-panel-header">
                    <button class="btn-back" onclick="triggerBack()"><i class="bi bi-arrow-left"></i> Back</button>
                    <div class="tool-panel-title"><i class="bi bi-envelope-x-fill"></i> Unbind Email</div>
                </div>
                
                <div id="unb-stage-init">
                    <div class="form-item">
                        <input type="text" class="form-input" id="unb-token-in" placeholder=" ">
                        <label>Access Token</label>
                    </div>
                    <button class="btn btn-full" onclick="unbindLoadProfile()">Load Account Setup</button>
                </div>

                <div id="unb-stage-flow" style="display: none;">
                    <div class="res-container" style="margin-bottom: 0.75rem;">
                        <span class="res-lbl">Current Linked Email</span>
                        <span class="res-val" id="unb-meta-email">-</span>
                    </div>

                    <div class="toggle-row">
                        <button class="toggle-btn active" id="unb-toggle-otp" onclick="toggleUnbMethod('otp')">OTP Code</button>
                        <button class="toggle-btn" id="unb-toggle-sec" onclick="toggleUnbMethod('sec')">Security Pin</button>
                    </div>

                    <div id="unb-form-otp">
                        <button class="btn btn-sec btn-full" onclick="unbindSendOtp()" style="margin-bottom: 0.75rem;">Send OTP</button>
                        <div class="form-item">
                            <input type="text" class="form-input" id="unb-otp-code" placeholder=" ">
                            <label>OTP Code</label>
                        </div>
                        <button class="btn btn-full" onclick="unbindVerifyIdentityOtp()">Validate Code</button>
                    </div>

                    <div id="unb-form-sec" style="display: none;">
                        <div class="form-item">
                            <input type="password" class="form-input" id="unb-sec-code" placeholder=" " maxlength="6" inputmode="numeric">
                            <label>6-Digit Security PIN</label>
                        </div>
                        <button class="btn btn-full" onclick="unbindVerifyIdentitySec()">Validate PIN</button>
                    </div>

                    <div id="unb-stage-final" style="display: none; margin-top: 1rem;">
                        <button class="btn btn-danger btn-full" onclick="promptUnbindSubmission()">Submit Unbind Action</button>
                    </div>
                </div>
            </div>

            <!-- Panel 4: Change Bind Email -->
            <div class="tool-panel" id="tool-change-bind">
                <div class="tool-panel-header">
                    <button class="btn-back" onclick="triggerBack()"><i class="bi bi-arrow-left"></i> Back</button>
                    <div class="tool-panel-title"><i class="bi bi-arrow-repeat"></i> Change Bind Email</div>
                </div>
                <div class="flow-tracker">
                    <div class="flow-node active" id="node-ch-1">1</div>
                    <div class="flow-node" id="node-ch-2">2</div>
                    <div class="flow-node" id="node-ch-3">3</div>
                </div>

                <div id="ch-stage-init">
                    <div class="form-item">
                        <input type="text" class="form-input" id="ch-token-in" placeholder=" ">
                        <label>Access Token</label>
                    </div>
                    <button class="btn btn-full" onclick="changeLoadProfile()">Authenticate</button>
                </div>

                <div id="ch-stage-old" style="display: none;">
                    <div class="res-container" style="margin-bottom: 0.75rem;">
                        <span class="res-lbl">Current Bound Email</span>
                        <span class="res-val" id="ch-meta-email">-</span>
                    </div>

                    <div class="toggle-row">
                        <button class="toggle-btn active" id="ch-toggle-otp" onclick="toggleChMethod('otp')">OTP Code</button>
                        <button class="toggle-btn" id="ch-toggle-sec" onclick="toggleChMethod('sec')">Security Pin</button>
                    </div>

                    <div id="ch-form-otp">
                        <button class="btn btn-sec btn-full" onclick="changeSendOldOtp()" style="margin-bottom: 0.75rem;">Send OTP</button>
                        <div class="form-item">
                            <input type="text" class="form-input" id="ch-old-otp" placeholder=" ">
                            <label>OTP Code</label>
                        </div>
                        <button class="btn btn-full" onclick="changeVerifyOldOtp()">Validate Identity</button>
                    </div>

                    <div id="ch-form-sec" style="display: none;">
                        <div class="form-item">
                            <input type="password" class="form-input" id="ch-old-sec" placeholder=" " maxlength="6" inputmode="numeric">
                            <label>6-Digit Security PIN</label>
                        </div>
                        <button class="btn btn-full" onclick="changeVerifyOldSec()">Validate PIN</button>
                    </div>
                </div>

                <div id="ch-stage-new" style="display: none;">
                    <div class="form-item">
                        <input type="email" class="form-input" id="ch-new-mail" placeholder=" ">
                        <label>New Email Address</label>
                    </div>
                    <button class="btn btn-sec btn-full" onclick="changeSendNewOtp()" style="margin-bottom: 0.75rem;">Send OTP</button>
                    
                    <div class="form-item">
                        <input type="text" class="form-input" id="ch-new-otp" placeholder=" ">
                        <label>New OTP Code</label>
                    </div>
                    <button class="btn btn-full" onclick="changeVerifyNewOtp()">Verify New Email</button>
                </div>

                <div id="ch-stage-final" style="display: none;">
                    <button class="btn btn-full" onclick="executeChangeSubmit()">Confirm Email Rebind</button>
                </div>
            </div>

            <!-- Panel 5: Cancel Bind Request -->
            <div class="tool-panel" id="tool-cancel-bind">
                <div class="tool-panel-header">
                    <button class="btn-back" onclick="triggerBack()"><i class="bi bi-arrow-left"></i> Back</button>
                    <div class="tool-panel-title"><i class="bi bi-x-circle-fill"></i> Cancel Bind Request</div>
                </div>
                <div class="form-item">
                    <input type="text" class="form-input" id="cancel-token" placeholder=" ">
                    <label>Access Token</label>
                </div>
                <button class="btn btn-danger btn-full" onclick="promptCancelBind()">Cancel Scheduled Bind</button>
            </div>

            <!-- Panel 6: EAT to Access Token -->
            <div class="tool-panel" id="tool-eat-token">
                <div class="tool-panel-header">
                    <button class="btn-back" onclick="triggerBack()"><i class="bi bi-arrow-left"></i> Back</button>
                    <div class="tool-panel-title"><i class="bi bi-key-fill"></i> EAT → Access Token</div>
                </div>
                <div class="form-item">
                    <input type="text" class="form-input" id="eat-val-in" placeholder=" ">
                    <label>EAT URL or Key String</label>
                </div>
                <button class="btn btn-full" onclick="executeEatExchange()">Resolve Token</button>

                <div class="res-container" id="eat-res" style="display: none;">
                    <div class="res-title">Resolved Profile</div>
                    <div class="grid-2col">
                        <div class="res-item">
                            <span class="res-lbl">Nickname</span>
                            <span class="res-val" id="eat-meta-nick">-</span>
                        </div>
                        <div class="res-item">
                            <span class="res-lbl">UID</span>
                            <div class="res-val-wrapper">
                                <span class="res-val" id="eat-meta-uid">-</span>
                                <button class="btn-copy-micro" onclick="copyValue('eat-meta-uid')"><i class="bi bi-copy"></i></button>
                            </div>
                        </div>
                        <div class="res-item" style="grid-column: span 2;">
                            <span class="res-lbl">Access Token</span>
                            <div class="res-val-wrapper" style="align-items: flex-start;">
                                <span class="res-val" id="eat-meta-token" style="font-family: monospace; font-size: 0.65rem; word-break: break-all; max-height: 52px; overflow-y: auto;">-</span>
                                <button class="btn-copy-micro" onclick="copyValue('eat-meta-token')"><i class="bi bi-copy"></i></button>
                            </div>
                        </div>
                    </div>
                </div>
            </div>

            <!-- Panel 7: Revoke Access Token -->
            <div class="tool-panel" id="tool-revoke-token">
                <div class="tool-panel-header">
                    <button class="btn-back" onclick="triggerBack()"><i class="bi bi-arrow-left"></i> Back</button>
                    <div class="tool-panel-title"><i class="bi bi-shield-lock-fill"></i> Revoke Access Token</div>
                </div>
                <div class="form-item">
                    <input type="text" class="form-input" id="revoke-token-in" placeholder=" ">
                    <label>Access Token</label>
                </div>
                <button class="btn btn-danger btn-full" onclick="promptRevocation()">Revoke Access Key</button>
            </div>

        </main>
    </div>

    <!-- UI Modal Dialog Container -->
    <div id="modal-overlay" class="modal-overlay">
        <div class="modal-card">
            <div id="modal-icon" class="modal-icon-box warn">
                <i class="bi bi-exclamation-triangle"></i>
            </div>
            <h3 id="modal-title">Attention required</h3>
            <p id="modal-body">Would you like to authorize this request?</p>
            <div class="flex-btn-row">
                <button class="btn btn-sec btn-full" onclick="dismissModal()">Abort</button>
                <button class="btn btn-danger btn-full" id="modal-primary-action">Confirm</button>
            </div>
        </div>
    </div>

    <!-- API Process Overlay -->
    <div id="loading-overlay">
        <div class="mini-spinner"></div>
    </div>

    <!-- Toasts Shelf -->
    <div id="toast-shelf"></div>

    <!-- Navigation Engine and API Interactions -->
    <script>
        let activeUnbMethod = 'otp';
        let activeChMethod = 'otp';
        let activeModalAction = null;
        
        let globalState = {
            accessToken: '',
            oldEmail: '',
            newEmail: '',
            identityToken: '',
            verifierToken: ''
        };

        // Custom router state tracks history
        let routerState = {
            screen: 'login', // 'login', 'dashboard', 'tool'
            toolId: null,
            step: 1
        };

        // Initialize state on window load
        window.onload = function() {
            const isAuth = sessionStorage.getItem('ckr_authorized') === 'true';
            if (isAuth) {
                const initDashboard = { screen: 'dashboard', toolId: null, step: 1 };
                history.replaceState(initDashboard, '');
                renderScreen(initDashboard, false);
            } else {
                const initLogin = { screen: 'login', toolId: null, step: 1 };
                history.replaceState(initLogin, '');
                renderScreen(initLogin, false);
            }
        };

        // Synchronize browser history pops
        window.addEventListener('popstate', function(event) {
            if (event.state) {
                // If popping back to login while active session exists
                if (event.state.screen === 'login' && sessionStorage.getItem('ckr_authorized') === 'true') {
                    // Re-push dashboard state to history
                    const currentDashState = { screen: 'dashboard', toolId: null, step: 1 };
                    history.pushState(currentDashState, '');
                    
                    promptModal(
                        'Exit CKRPRO?',
                        'Confirm exiting administrative console and locking tool sessions.',
                        () => {
                            executeLogout();
                        }
                    );
                    return;
                }
                renderScreen(event.state, true);
            }
        });

        // Main dynamic routing trigger
        function navigate(screen, toolId = null, step = 1, isBack = false) {
            const nextState = { screen, toolId, step };
            history.pushState(nextState, '');
            renderScreen(nextState, isBack);
        }

        function triggerBack() {
            history.back();
        }

        // Direct DOM renderer according to routerState
        function renderScreen(state, isBack = false) {
            setProcessing(true); // Pre-load step blocks multiple clicks (250ms)

            setTimeout(() => {
                setProcessing(false);
                routerState = state;

                // Strip transition classes from elements
                const screens = document.querySelectorAll('.screen');
                screens.forEach(s => {
                    s.classList.remove('active', 'slide-up-in', 'slide-right-in');
                });

                if (state.screen === 'login') {
                    const loginScreen = document.getElementById('login-screen');
                    loginScreen.classList.add('active');
                    loginScreen.classList.add(isBack ? 'slide-right-in' : 'slide-up-in');
                } 
                else if (state.screen === 'dashboard') {
                    const dashboardScreen = document.getElementById('dashboard-screen');
                    dashboardScreen.classList.add('active');
                    dashboardScreen.classList.add(isBack ? 'slide-right-in' : 'slide-up-in');
                    
                    document.getElementById('main-menu-grid').style.display = 'grid';
                    document.querySelectorAll('.tool-panel').forEach(panel => panel.style.display = 'none');
                } 
                else if (state.screen === 'tool') {
                    const dashboardScreen = document.getElementById('dashboard-screen');
                    dashboardScreen.classList.add('active');
                    dashboardScreen.classList.add(isBack ? 'slide-right-in' : 'slide-up-in');

                    document.getElementById('main-menu-grid').style.display = 'none';
                    document.querySelectorAll('.tool-panel').forEach(panel => panel.style.display = 'none');
                    
                    const panel = document.getElementById(state.toolId);
                    if (panel) {
                        panel.style.display = 'block';
                        renderToolSteps(state.toolId, state.step);
                    }
                }
            }, 250);
        }

        // Handles wizard visibility parameters based on step configuration
        function renderToolSteps(toolId, step) {
            if (toolId === 'tool-bind-email') {
                updateBindStepNode(step);
                document.getElementById('bind-step1-wrapper').style.display = step === 1 ? 'block' : 'none';
                document.getElementById('bind-step2-wrapper').style.display = step === 2 ? 'block' : 'none';
                document.getElementById('bind-step3-wrapper').style.display = step === 3 ? 'block' : 'none';

                document.getElementById('btn-bind-otp').style.display = step === 1 ? 'inline-flex' : 'none';
                document.getElementById('btn-bind-verify').style.display = step === 2 ? 'inline-flex' : 'none';
                document.getElementById('btn-bind-apply').style.display = step === 3 ? 'inline-flex' : 'none';
                document.getElementById('btn-bind-reset').style.display = step > 1 ? 'inline-flex' : 'none';
            }
            else if (toolId === 'tool-unbind-email') {
                document.getElementById('unb-stage-init').style.display = step === 1 ? 'block' : 'none';
                document.getElementById('unb-stage-flow').style.display = step === 2 ? 'block' : 'none';
                document.getElementById('unb-stage-final').style.display = step === 3 ? 'block' : 'none';
            }
            else if (toolId === 'tool-change-bind') {
                updateChangeStepNode(step);
                document.getElementById('ch-stage-init').style.display = step === 1 ? 'block' : 'none';
                document.getElementById('ch-stage-old').style.display = step === 2 ? 'block' : 'none';
                document.getElementById('ch-stage-new').style.display = step === 3 ? 'block' : 'none';
                document.getElementById('ch-stage-final').style.display = step === 4 ? 'block' : 'none';
            }
        }

        // Helper target switcher for grid elements
        function routeToTool(toolId, step = 1) {
            navigate('tool', toolId, step, false);
        }

        // --- System Core Actions ---
        function executeLogin() {
            const pwd = document.getElementById('portal-pwd').value;
            if (pwd === 'ckr') {
                sessionStorage.setItem('ckr_authorized', 'true');
                dispatchToast('Access authorized.', 'success');
                
                const loginScreen = document.getElementById('login-screen');
                loginScreen.classList.add('slide-up-in');
                navigate('dashboard', null, 1, false);
            } else {
                const card = document.getElementById('login-card-anim');
                card.classList.add('shake-it');
                dispatchToast('Incorrect credentials.', 'error');
                setTimeout(() => card.classList.remove('shake-it'), 400);
            }
        }

        function promptLogout() {
            promptModal(
                'Lock Active Console',
                'Confirm logging out and returning to authentication portal.',
                executeLogout
            );
        }

        function executeLogout() {
            sessionStorage.removeItem('ckr_authorized');
            // Hard clean navigation history states, push fresh login state
            const cleanState = { screen: 'login', toolId: null, step: 1 };
            history.replaceState(cleanState, '');
            renderScreen(cleanState, true);
        }

        // --- Processing Loader Indicator ---
        function setProcessing(active) {
            const el = document.getElementById('loading-overlay');
            if (active) el.classList.add('active');
            else el.classList.remove('active');
        }

        // --- Dynamic Toast Dispatches ---
        function dispatchToast(msg, type = 'info') {
            const shelf = document.getElementById('toast-shelf');
            const toast = document.createElement('div');
            toast.className = `toast-entity ${type}`;

            let icon = 'info-circle';
            if (type === 'success') icon = 'check-circle';
            if (type === 'error') icon = 'exclamation-circle';
            if (type === 'warning') icon = 'exclamation-triangle';

            toast.innerHTML = `<i class="bi bi-${icon}"></i><span>${msg}</span>`;
            shelf.appendChild(toast);

            setTimeout(() => toast.classList.add('show'), 10);
            setTimeout(() => {
                toast.classList.remove('show');
                setTimeout(() => toast.remove(), 250);
            }, 3500);
        }

        // --- Dynamic Modals Component ---
        function promptModal(title, text, actionCallback, statusType = 'warn') {
            document.getElementById('modal-title').innerText = title;
            document.getElementById('modal-body').innerText = text;
            
            const iconBox = document.getElementById('modal-icon');
            iconBox.className = `modal-icon-box ${statusType}`;
            
            const iconEl = iconBox.querySelector('i');
            if (statusType === 'success') iconEl.className = 'bi bi-check-lg';
            else if (statusType === 'error') iconEl.className = 'bi bi-x-lg';
            else iconEl.className = 'bi bi-exclamation-triangle';

            activeModalAction = actionCallback;
            document.getElementById('modal-overlay').classList.add('active');
        }

        function dismissModal() {
            document.getElementById('modal-overlay').classList.remove('active');
            activeModalAction = null;
        }

        document.getElementById('modal-primary-action').addEventListener('click', () => {
            if (typeof activeModalAction === 'function') {
                activeModalAction();
            }
            dismissModal();
        });

        // Copy Elements to Clipboard
        function copyValue(id) {
            const el = document.getElementById(id);
            if (!el) return;
            const textVal = el.innerText.trim();
            if (!textVal || textVal === '-' || textVal === 'None') {
                dispatchToast('Nothing to copy.', 'warning');
                return;
            }

            navigator.clipboard.writeText(textVal).then(() => {
                dispatchToast('Copied to clipboard!', 'success');
            }).catch(() => {
                dispatchToast('Failed copy action.', 'error');
            });
        }

        function togglePassVisibility(id) {
            const el = document.getElementById(id);
            if (el) {
                el.type = el.type === 'password' ? 'text' : 'password';
            }
        }

        function cleanTimeFormat(seconds) {
            if (!seconds || isNaN(seconds)) return 'None';
            let d = Math.floor(seconds / 86400);
            let h = Math.floor((seconds % 86400) / 3600);
            let m = Math.floor((seconds % 3600) / 60);
            return `${d}d ${h}h ${m}m`;
        }

        // ================== CHECK BIND INFO ACTIONS ==================
        function executeCheckBind() {
            const token = document.getElementById('chk-token').value.trim();
            if (!token) {
                dispatchToast('Please enter an Access Token.', 'warning');
                return;
            }

            setProcessing(true);
            fetch('/api/check_bind', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ access_token: token })
            })
            .then(res => res.json())
            .then(data => {
                setProcessing(false);
                if (data.success) {
                    document.getElementById('chk-res').style.display = 'block';
                    document.getElementById('val-uid').innerText = data.player.uid || 'Unknown';
                    document.getElementById('val-nick').innerText = data.player.nickname || 'Unknown';
                    document.getElementById('val-reg').innerText = data.player.region || 'Unknown';
                    
                    const bind = data.bind || {};
                    document.getElementById('val-email').innerText = bind.email || 'None';
                    document.getElementById('val-pending').innerText = bind.email_to_be || 'None';
                    
                    const countdown = parseInt(bind.request_exec_countdown);
                    document.getElementById('val-time').innerText = countdown > 0 ? cleanTimeFormat(countdown) : 'No request pending';
                    document.getElementById('val-status').innerText = bind.result === 0 ? 'Success' : `Error (${bind.result})`;
                    
                    dispatchToast('Data loaded.', 'success');
                } else {
                    dispatchToast(data.error || 'Request rejected.', 'error');
                }
            })
            .catch(() => {
                setProcessing(false);
                dispatchToast('Network failure.', 'error');
            });
        }

        // ================== BIND EMAIL ACTIONS ==================
        function updateBindStepNode(stepNum) {
            document.querySelectorAll('#node-bind-1, #node-bind-2, #node-bind-3').forEach((node, idx) => {
                const nodeStep = idx + 1;
                node.className = 'flow-node';
                if (nodeStep === stepNum) node.classList.add('active');
                else if (nodeStep < stepNum) node.classList.add('completed');
            });
        }

        function resetBindFlow() {
            document.getElementById('bind-token-in').disabled = false;
            document.getElementById('bind-mail-in').disabled = false;
            document.getElementById('bind-otp-in').value = '';
            document.getElementById('bind-pin-in').value = '';
            globalState.verifierToken = '';
            navigate('tool', 'tool-bind-email', 1, true);
        }

        function bindEmailSendOTP() {
            const token = document.getElementById('bind-token-in').value.trim();
            const email = document.getElementById('bind-mail-in').value.trim();

            if (!token || !email) {
                dispatchToast('All initial input parameters required.', 'warning');
                return;
            }

            setProcessing(true);
            fetch('/api/send_otp', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ email: email, access_token: token })
            })
            .then(res => res.json())
            .then(resData => {
                setProcessing(false);
                if (resData.success && resData.data.result === 0) {
                    dispatchToast('OTP sent to email.', 'success');
                    document.getElementById('bind-token-in').disabled = true;
                    document.getElementById('bind-mail-in').disabled = true;
                    
                    navigate('tool', 'tool-bind-email', 2, false);
                } else {
                    dispatchToast(resData.data?.error || 'Failed sending verification OTP.', 'error');
                }
            })
            .catch(() => {
                setProcessing(false);
                dispatchToast('Network timed out.', 'error');
            });
        }

        function bindEmailVerifyOTP() {
            const token = document.getElementById('bind-token-in').value.trim();
            const email = document.getElementById('bind-mail-in').value.trim();
            const otp = document.getElementById('bind-otp-in').value.trim();

            if (!otp) {
                dispatchToast('Enter OTP to continue.', 'warning');
                return;
            }

            setProcessing(true);
            fetch('/api/verify_otp', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ email: email, access_token: token, otp: otp })
            })
            .then(res => res.json())
            .then(resData => {
                setProcessing(false);
                if (resData.success && resData.verifier_token) {
                    globalState.verifierToken = resData.verifier_token;
                    dispatchToast('Security OTP confirmed.', 'success');
                    
                    navigate('tool', 'tool-bind-email', 3, false);
                } else {
                    dispatchToast('Invalid verification key parameter.', 'error');
                }
            })
            .catch(() => {
                setProcessing(false);
                dispatchToast('Request failed.', 'error');
            });
        }

        function bindEmailComplete() {
            const token = document.getElementById('bind-token-in').value.trim();
            const email = document.getElementById('bind-mail-in').value.trim();
            const pin = document.getElementById('bind-pin-in').value.trim();

            if (!pin || pin.length < 6) {
                dispatchToast('Pin parameter invalid.', 'warning');
                return;
            }

            setProcessing(true);
            fetch('/api/create_bind', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({
                    email: email,
                    access_token: token,
                    verifier_token: globalState.verifierToken,
                    security_code: pin
                })
            })
            .then(res => res.json())
            .then(resData => {
                setProcessing(false);
                if (resData.success && resData.data.result === 0) {
                    promptModal('Operation Successful', 'Your request has been filed successfully.', () => {
                        resetBindFlow();
                        triggerBack();
                    }, 'success');
                } else {
                    dispatchToast(resData.data?.error || 'Bind sequence failed.', 'error');
                }
            })
            .catch(() => {
                setProcessing(false);
                dispatchToast('Server error.', 'error');
            });
        }

        // ================== UNBIND EMAIL ACTIONS ==================
        function toggleUnbMethod(method) {
            activeUnbMethod = method;
            document.getElementById('unb-toggle-otp').className = method === 'otp' ? 'toggle-btn active' : 'toggle-btn';
            document.getElementById('unb-toggle-sec').className = method === 'sec' ? 'toggle-btn active' : 'toggle-btn';
            
            document.getElementById('unb-form-otp').style.display = method === 'otp' ? 'block' : 'none';
            document.getElementById('unb-form-sec').style.display = method === 'sec' ? 'block' : 'none';
        }

        function unbindLoadProfile() {
            const token = document.getElementById('unb-token-in').value.trim();
            if (!token) {
                dispatchToast('Enter Access Token.', 'warning');
                return;
            }

            setProcessing(true);
            fetch('/api/check_bind', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ access_token: token })
            })
            .then(res => res.json())
            .then(data => {
                setProcessing(false);
                if (data.success) {
                    const email = data.bind.email;
                    if (!email) {
                        dispatchToast('Verification route is unbound.', 'error');
                        return;
                    }
                    globalState.accessToken = token;
                    globalState.oldEmail = email;
                    document.getElementById('unb-meta-email').innerText = email;
                    
                    navigate('tool', 'tool-unbind-email', 2, false);
                    toggleUnbMethod('otp');
                } else {
                    dispatchToast('Profile verification failure.', 'error');
                }
            })
            .catch(() => {
                setProcessing(false);
                dispatchToast('Request failed.', 'error');
            });
        }

        function unbindSendOtp() {
            setProcessing(true);
            fetch('/api/send_otp', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ email: globalState.oldEmail, access_token: globalState.accessToken })
            })
            .then(res => res.json())
            .then(resData => {
                setProcessing(false);
                if (resData.success && resData.data.result === 0) {
                    dispatchToast('Verification OTP dispatched.', 'success');
                } else {
                    dispatchToast('Failed dispatching security validation OTP.', 'error');
                }
            })
            .catch(() => {
                setProcessing(false);
                dispatchToast('Network timed out.', 'error');
            });
        }

        function unbindVerifyIdentityOtp() {
            const otp = document.getElementById('unb-otp-code').value.trim();
            if (!otp) {
                dispatchToast('OTP parameter missing.', 'warning');
                return;
            }
            setProcessing(true);
            fetch('/api/verify_identity', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ email: globalState.oldEmail, access_token: globalState.accessToken, otp: otp })
            })
            .then(res => res.json())
            .then(resData => {
                setProcessing(false);
                if (resData.success && resData.identity_token) {
                    globalState.identityToken = resData.identity_token;
                    navigate('tool', 'tool-unbind-email', 3, false);
                    dispatchToast('Identity confirmed.', 'success');
                } else {
                    dispatchToast('Confirmation rejected.', 'error');
                }
            })
            .catch(() => {
                setProcessing(false);
                dispatchToast('Network execution failure.', 'error');
            });
        }

        function unbindVerifyIdentitySec() {
            const sec = document.getElementById('unb-sec-code').value.trim();
            if (!sec) {
                dispatchToast('PIN code input missing.', 'warning');
                return;
            }
            setProcessing(true);
            fetch('/api/verify_identity', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ email: globalState.oldEmail, access_token: globalState.accessToken, secondary_password: sec })
            })
            .then(res => res.json())
            .then(resData => {
                setProcessing(false);
                if (resData.success && resData.identity_token) {
                    globalState.identityToken = resData.identity_token;
                    navigate('tool', 'tool-unbind-email', 3, false);
                    dispatchToast('Identity confirmed.', 'success');
                } else {
                    dispatchToast('Verification rejected.', 'error');
                }
            })
            .catch(() => {
                setProcessing(false);
                dispatchToast('Verification network failure.', 'error');
            });
        }

        function promptUnbindSubmission() {
            promptModal(
                'Confirm Account Unbind',
                'Unbinding the active verification mail is permanent. Do you accept this instruction?',
                executeUnbindAction
            );
        }

        function executeUnbindAction() {
            setProcessing(true);
            fetch('/api/create_unbind', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ identity_token: globalState.identityToken, access_token: globalState.accessToken })
            })
            .then(res => res.json())
            .then(resData => {
                setProcessing(false);
                if (resData.success && resData.data.result === 0) {
                    promptModal('Unbind Successful', 'Your request has been successfully submitted.', () => {
                        window.location.reload();
                    }, 'success');
                } else {
                    dispatchToast('Operation denied by Registry.', 'error');
                }
            })
            .catch(() => {
                setProcessing(false);
                dispatchToast('Server error.', 'error');
            });
        }

        // ================== CHANGE BIND EMAIL ACTIONS ==================
        function updateChangeStepNode(stepNum) {
            document.querySelectorAll('#node-ch-1, #node-ch-2, #node-ch-3').forEach((node, idx) => {
                const nodeStep = idx + 1;
                node.className = 'flow-node';
                if (nodeStep === stepNum || (stepNum === 4 && nodeStep === 3)) node.classList.add('active');
                else if (nodeStep < stepNum) node.classList.add('completed');
            });
        }

        function toggleChMethod(method) {
            activeChMethod = method;
            document.getElementById('ch-toggle-otp').className = method === 'otp' ? 'toggle-btn active' : 'toggle-btn';
            document.getElementById('ch-toggle-sec').className = method === 'sec' ? 'toggle-btn active' : 'toggle-btn';
            
            document.getElementById('ch-form-otp').style.display = method === 'otp' ? 'block' : 'none';
            document.getElementById('ch-form-sec').style.display = method === 'sec' ? 'block' : 'none';
        }

        function changeLoadProfile() {
            const token = document.getElementById('ch-token-in').value.trim();
            if (!token) {
                dispatchToast('Access Token field required.', 'warning');
                return;
            }

            setProcessing(true);
            fetch('/api/check_bind', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ access_token: token })
            })
            .then(res => res.json())
            .then(data => {
                setProcessing(false);
                if (data.success) {
                    const email = data.bind.email;
                    if (!email) {
                        dispatchToast('No active email configured.', 'error');
                        return;
                    }
                    globalState.accessToken = token;
                    globalState.oldEmail = email;
                    document.getElementById('ch-meta-email').innerText = email;
                    
                    navigate('tool', 'tool-change-bind', 2, false);
                    toggleChMethod('otp');
                } else {
                    dispatchToast('Verification error.', 'error');
                }
            })
            .catch(() => {
                setProcessing(false);
                dispatchToast('Connection failed.', 'error');
            });
        }

        function changeSendOldOtp() {
            setProcessing(true);
            fetch('/api/send_otp', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ email: globalState.oldEmail, access_token: globalState.accessToken })
            })
            .then(res => res.json())
            .then(resData => {
                setProcessing(false);
                if (resData.success && resData.data.result === 0) {
                    dispatchToast('OTP validation sent.', 'success');
                } else {
                    dispatchToast('Unrecognized profile validation parameters.', 'error');
                }
            })
            .catch(() => {
                setProcessing(false);
                dispatchToast('Network timed out.', 'error');
            });
        }

        function changeVerifyOldOtp() {
            const otp = document.getElementById('ch-old-otp').value.trim();
            if (!otp) {
                dispatchToast('OTP required.', 'warning');
                return;
            }
            setProcessing(true);
            fetch('/api/verify_identity', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ email: globalState.oldEmail, access_token: globalState.accessToken, otp: otp })
            })
            .then(res => res.json())
            .then(resData => {
                setProcessing(false);
                if (resData.success && resData.identity_token) {
                    globalState.identityToken = resData.identity_token;
                    navigate('tool', 'tool-change-bind', 3, false);
                    dispatchToast('Identity confirmed.', 'success');
                } else {
                    dispatchToast('Confirmation parameters rejected.', 'error');
                }
            })
            .catch(() => {
                setProcessing(false);
                dispatchToast('Server error.', 'error');
            });
        }

        function changeVerifyOldSec() {
            const sec = document.getElementById('ch-old-sec').value.trim();
            if (!sec) {
                dispatchToast('Validation Code required.', 'warning');
                return;
            }
            setProcessing(true);
            fetch('/api/verify_identity', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ email: globalState.oldEmail, access_token: globalState.accessToken, secondary_password: sec })
            })
            .then(res => res.json())
            .then(resData => {
                setProcessing(false);
                if (resData.success && resData.identity_token) {
                    globalState.identityToken = resData.identity_token;
                    navigate('tool', 'tool-change-bind', 3, false);
                    dispatchToast('Identity confirmed.', 'success');
                } else {
                    dispatchToast('Invalid PIN parameters.', 'error');
                }
            })
            .catch(() => {
                setProcessing(false);
                dispatchToast('Server connection failed.', 'error');
            });
        }

        function changeSendNewOtp() {
            const newMail = document.getElementById('ch-new-mail').value.trim();
            if (!newMail) {
                dispatchToast('Enter destination email address.', 'warning');
                return;
            }
            setProcessing(true);
            fetch('/api/send_otp', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ email: newMail, access_token: globalState.accessToken })
            })
            .then(res => res.json())
            .then(resData => {
                setProcessing(false);
                if (resData.success && resData.data.result === 0) {
                    globalState.newEmail = newMail;
                    dispatchToast('Validation OTP sent.', 'success');
                } else {
                    dispatchToast('Failed dispatching verification OTP.', 'error');
                }
            })
            .catch(() => {
                setProcessing(false);
                dispatchToast('Timeout error.', 'error');
            });
        }

        function changeVerifyNewOtp() {
            const otp = document.getElementById('ch-new-otp').value.trim();
            if (!otp) {
                dispatchToast('Enter new OTP validation code.', 'warning');
                return;
            }
            setProcessing(true);
            fetch('/api/verify_otp', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ email: globalState.newEmail, access_token: globalState.accessToken, otp: otp })
            })
            .then(res => res.json())
            .then(resData => {
                setProcessing(false);
                if (resData.success && resData.verifier_token) {
                    globalState.verifierToken = resData.verifier_token;
                    navigate('tool', 'tool-change-bind', 4, false);
                    dispatchToast('New validation code confirmed.', 'success');
                } else {
                    dispatchToast('Failed validating confirmation parameters.', 'error');
                }
            })
            .catch(() => {
                setProcessing(false);
                dispatchToast('Execution failed.', 'error');
            });
        }

        function executeChangeSubmit() {
            setProcessing(true);
            fetch('/api/create_rebind', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({
                    identity_token: globalState.identityToken,
                    email: globalState.newEmail,
                    verifier_token: globalState.verifierToken,
                    access_token: globalState.accessToken
                })
            })
            .then(res => res.json())
            .then(resData => {
                setProcessing(false);
                if (resData.success && resData.data.result === 0) {
                    promptModal('Change Successful', 'Your request has been successfully submitted.', () => {
                        window.location.reload();
                    }, 'success');
                } else {
                    dispatchToast('Validation rejected by Registry.', 'error');
                }
            })
            .catch(() => {
                setProcessing(false);
                dispatchToast('Network timed out.', 'error');
            });
        }

        // ================== CANCEL BIND REQUEST ACTIONS ==================
        function promptCancelBind() {
            const token = document.getElementById('cancel-token').value.trim();
            if (!token) {
                dispatchToast('Access Token parameter required.', 'warning');
                return;
            }
            promptModal(
                'Cancel Bind Request',
                'Do you confirm canceling scheduled verification route updates?',
                executeCancelBindAction
            );
        }

        function executeCancelBindAction() {
            const token = document.getElementById('cancel-token').value.trim();
            setProcessing(true);
            fetch('/api/cancel_bind', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ access_token: token })
            })
            .then(res => res.json())
            .then(resData => {
                setProcessing(false);
                if (resData.success && resData.data.result === 0) {
                    promptModal('Aborted Successfully', 'All pending countdown actions cleared.', () => {
                        document.getElementById('cancel-token').value = '';
                        triggerBack();
                    }, 'success');
                } else {
                    dispatchToast('Failed canceling pending binds.', 'error');
                }
            })
            .catch(() => {
                setProcessing(false);
                dispatchToast('Network connection lost.', 'error');
            });
        }

        // ================== EAT TO ACCESS TOKEN ACTIONS ==================
        function executeEatExchange() {
            const rawEat = document.getElementById('eat-val-in').value.trim();
            if (!rawEat) {
                dispatchToast('Enter EAT Token value.', 'warning');
                return;
            }
            setProcessing(true);
            fetch('/api/eat_to_token', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ eat_input: rawEat })
            })
            .then(res => res.json())
            .then(data => {
                setProcessing(false);
                if (data.success) {
                    document.getElementById('eat-res').style.display = 'block';
                    document.getElementById('eat-meta-nick').innerText = data.nickname || 'Unknown';
                    document.getElementById('eat-meta-uid').innerText = data.account_id || 'Unknown';
                    
                    const tokenNode = document.getElementById('eat-meta-token');
                    tokenNode.innerText = data.access_token || '-';
                    
                    dispatchToast('Resolved credentials.', 'success');
                } else {
                    dispatchToast(data.error || 'Parsing operation rejected.', 'error');
                }
            })
            .catch(() => {
                setProcessing(false);
                dispatchToast('Server error.', 'error');
            });
        }

        // ================== REVOKE ACCESS TOKEN ACTIONS ==================
        function promptRevocation() {
            const token = document.getElementById('revoke-token-in').value.trim();
            if (!token) {
                dispatchToast('Access Token parameter required.', 'warning');
                return;
            }
            promptModal(
                'Confirm Key Revocation',
                'This will destroy all active credential authorization sessions. Do you accept?',
                executeRevokeAction
            );
        }

        function executeRevokeAction() {
            const token = document.getElementById('revoke-token-in').value.trim();
            setProcessing(true);
            fetch('/api/revoke_token', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ access_token: token })
            })
            .then(res => res.json())
            .then(data => {
                setProcessing(false);
                if (data.success) {
                    promptModal('Revoked', 'Security validation slot cleared.', () => {
                        document.getElementById('revoke-token-in').value = '';
                        triggerBack();
                    }, 'success');
                } else {
                    dispatchToast(data.error || 'Revocation parameter validation error.', 'error');
                }
            })
            .catch(() => {
                setProcessing(false);
                dispatchToast('Network timed out.', 'error');
            });
        }
    </script>
</body>
</html>
"""

@app.route('/')
def index():
    return render_template_string(HTML_TEMPLATE)

# Exposure alias for Vercel
app_wrapper = app

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)