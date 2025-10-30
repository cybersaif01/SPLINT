from flask import Flask, request, jsonify
import subprocess

app = Flask(__name__)

@app.route('/block_usb', methods=['POST'])
def block_usb():
    try:
        ps_script = r'''
        Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\USBSTOR" -Name "Start" -Value 4
        '''
        subprocess.run(["powershell", "-Command", ps_script], check=True)
        return jsonify({"status": "success", "message": "USB blocked"}), 200
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 500

if __name__ == "__main__":
    app.run(host='0.0.0.0', port=9000)
