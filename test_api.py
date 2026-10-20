import requests

BASE_URL = "http://127.0.0.1:5000"

print("--- 测试 1: 无 Token 访问 (预期 401) ---")
r = requests.get(f"{BASE_URL}/api/data")
print(r.status_code, r.text)

print("\n--- 测试 2: 登录获取 Token ---")
r = requests.post(f"{BASE_URL}/auth/login", json={"username": "alice", "password": "password123"})
print(r.status_code, r.text)
token = r.json().get("token")

if token:
    headers = {"Authorization": f"Bearer {token}"}
    
    print("\n--- 测试 3: 带 Token 访问数据 ---")
    r = requests.get(f"{BASE_URL}/api/data", headers=headers)
    print(r.status_code, r.text)
    
    print("\n--- 测试 4: 验证 XSS 防护 ---")
    payload = {"title": "test", "content": "<script>alert(1)</script>"}
    r = requests.post(f"{BASE_URL}/api/posts", json=payload, headers=headers)
    print(r.status_code, r.text)