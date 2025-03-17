import jwt
token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VyX2lkIjoiMDY3ZDZlYzctNGE2OC03ZDJlLTgwMDAtY2MxYjkwNjQyZTJhIiwiZXhwIjoxNzQyMzkxMTcyLCJ0eXBlIjoiYWNjZXNzIn0.QHNVgKMXnT3PEVRUgjm329XcoTgdsP8IvgML8hE4vCs"
decoded = jwt.decode(token, options={"verify_signature": False})  # Disable signature verification for debugging
print(decoded)
