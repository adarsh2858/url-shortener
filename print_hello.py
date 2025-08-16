import yaml

with open('hi.yaml','r') as f:
    data = yaml.safe_load(f)

print(data['message'])
