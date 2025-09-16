# Advanced API Tester – Burp Suite Extension

Automated API security testing inside Burp Suite: import API definitions, run admin-vs-user differential scans, and instantly spot access-control flaws through color-coded results.

---

## ✨ Features
- **Multi-format import**: JSON, OpenAPI/Swagger, WSDL, Postman collections  
- **Burp history integration**: add captured requests with one click  
- **Differential analysis**: compares admin vs user responses for auth-z issues  
- **Color-coded table**: red (vulnerable) / green (safe) status indicators  
- **Flexible auth headers**: set distinct tokens or cookies per role  
- **Enhanced viewer**: side-by-side request/response tabs  
- **Remote spec loading**: fetch API definitions by URL  

---

## 🚀 Installation
1. Download the latest `.jar` from [releases](./releases).  
2. In Burp Suite, go to **Extender → Extensions → Add**.  
3. Select **Java** as the type and choose the downloaded file.  
4. Click **Next** to load the extension.

---

## 📋 Requirements
- Burp Suite Community or Professional  
- Java 8+  

---

## 🎯 Usage

| Step | Action | Details |
|------|--------|---------|
| 1 | **Load API** | Click **Load API Definition**, **Load URL**, or **Import from Burp History** |
| 2 | **Set Auth** | Fill **Admin Headers** and **User Headers** panels |
| 3 | **Run Tests** | Press **Run Vulnerability Tests**; progress shows in real time |
| 4 | **Review** | Red rows = potential vuln, green = safe; click a row for full messages |

Example results:
Method URL Admin User Vulnerability
POST /api/admin/delete-user 200 200 VULNERABLE
GET /api/user/profile 200 200 Safe

---

## 🛡️ Detection Logic
1. Compare HTTP status codes.  
2. Measure body length difference.  
3. Compute body similarity; > 90 % with identical codes flags a potential bypass.  

---

## 🔧 Supported Formats

| Format | Description |
|--------|-------------|
| **OpenAPI / Swagger** | Standard JSON specs |
| **Postman Collection** | V2 JSON exports |
| **WSDL** | SOAP service definitions |
| **Burp History** | Proxy-captured requests |

---

## 🤝 Contributing
1. Fork the repo.  
2. Create a feature branch: `git checkout -b feature/my-change`  
3. Commit and push: `git commit -m "Add cool feature"`  
4. Open a Pull Request.  

---

## 📝 License
Distributed under the MIT License. See `LICENSE` for details.

---

> **Disclaimer**  
> Use this tool only against systems you have explicit permission to test.

---

⭐ **Star this repo if it helps your testing workflow!**
