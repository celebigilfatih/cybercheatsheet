import json

try:
    with open(r'c:\Users\cihan\cybercheatsheet\mdb\cheatsheets.json', 'r', encoding='utf-8') as f:
        data = json.load(f)
    print("JSON is valid")
    print(f"Number of items: {len(data)}")
except Exception as e:
    print(f"JSON validation error: {e}")