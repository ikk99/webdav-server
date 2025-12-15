#!/usr/bin/env python3
from web_interface import create_web_app

app = create_web_app()

if __name__ == "__main__":
    print("启动 Web 界面...")
    app.run(host="0.0.0.0", port=5000, debug=True)
