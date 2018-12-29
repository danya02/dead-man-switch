#!/usr/bin/python3
import os
print('Generating client keys...')
os.system('openssl genrsa -out client-priv.pem 8192')
os.system('pyrsa-priv2pub -i client-priv.pem -o client-pub.pem')

print('Generating server keys...')
os.system('openssl genrsa -out server-priv.pem 8192')
os.system('pyrsa-priv2pub -i server-priv.pem -o server-pub.pem')
