import json

# Read the original file
with open(r'c:\Users\cihan\cybercheatsheet\mdb\cheatsheets.json', 'r', encoding='utf-8') as f:
    lines = f.readlines()

# Process the lines to create a proper JSON array
# Each line is a separate JSON object
objects = []
for line in lines:
    line = line.strip()
    if line:  # Skip empty lines
        try:
            obj = json.loads(line)
            objects.append(obj)
        except json.JSONDecodeError as e:
            print(f"Error parsing line: {e}")
            print(f"Line content: {line}")

# Write the fixed JSON array to the file
with open(r'c:\Users\cihan\cybercheatsheet\mdb\cheatsheets.json', 'w', encoding='utf-8') as f:
    json.dump(objects, f, ensure_ascii=False, indent=2)

print("File fixed successfully!")