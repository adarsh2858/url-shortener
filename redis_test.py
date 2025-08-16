import redis

r = redis.Redis(host='localhost', port=6379, db=0)

r.set('url_shortener', 'Hello from python!')

value = r.get('url_shortener')
print(value)
