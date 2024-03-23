from flask import Flask, request, redirect, session
import requests

app = Flask(__name__)

# Shopify app credentials
API_KEY = '05c0c33a719e715e7f4d16411b617aa2'
API_SECRET = 'ba4ca4cec7834b2eb9dc86e43009ded1'
REDIRECT_URI = 'https://055d-2405-201-401b-df89-fc96-6497-8a29-4d30.ngrok-free.app/auth/callback'

# Shopify OAuth URLs
AUTH_URL = 'https://{shop}/admin/oauth/authorize?client_id={api_key}&scope=read_products,write_products&redirect_uri={redirect_uri}'
TOKEN_URL = 'https://{shop}/admin/oauth/access_token'

@app.route('/')
def home():
    shop = request.args.get('shop')
    if shop:
        return redirect(AUTH_URL.format(shop=shop, api_key=API_KEY, redirect_uri=REDIRECT_URI))
    else:
        return 'No shop parameter provided.'

@app.route('/auth/callback')
def callback():
    shop = request.args.get('shop')
    code = request.args.get('code')

    if not shop or not code:
        return 'Missing shop or code parameter.'

    try:
        # Exchange authorization code for access token
        response = requests.post(TOKEN_URL.format(shop=shop), json={
            'client_id': API_KEY,
            'client_secret': API_SECRET,
            'code': code
        })

        response_data = response.json()
        if 'access_token' in response_data:
            token = response_data['access_token']
            print(token)

            # Store the token in session (or your database)
            # session['shopify_token'] = token

            return 'Token generated successfully!'
        else:
            return 'Failed to get access token'
    except Exception as e:
        return f'Error: {str(e)}'

if __name__ == '__main__':
    app.run(debug=True)
