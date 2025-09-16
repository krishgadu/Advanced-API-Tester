Advanced API Tester streamlines API penetration testing by automatically importing API definitions, configuring authentication headers, and detecting authorization flaws through differential response analysis. Perfect for bug bounty hunters and security professionals testing complex API endpoints.

✨ Key Features
Multi-Format API Import: Supports JSON, OpenAPI/Swagger, WSDL, and Postman collections

Burp History Integration: Import requests directly from Burp Suite's proxy history

Differential Analysis: Compare admin vs user responses to identify access control issues

Color-Coded Results: Visual vulnerability indicators with red/green status coding

Custom Authentication: Flexible header configuration for multiple user roles

Request/Response Viewer: Enhanced tabs for detailed HTTP message analysis

Vulnerability Detection: Automated identification of authorization bypasses

Remote URL Loading: Import API definitions from remote endpoints

🚀 Installation
Download the .jar file from the releases page

Open Burp Suite → Extensions → Add

Select "Java" as extension type

Choose the downloaded .jar file

Click "Next" to load the extension

📋 Requirements
Burp Suite Professional or Community Edition

Java 8 or higher

API definition files (JSON/OpenAPI/WSDL/Postman)

🎯 Usage
1. Load API Definition
Click "Load API Definition" to import from file

Use "Load URL" for remote API specifications

Or "Import from Burp History" for existing requests

2. Configure Authentication
Admin Headers: Add privileged user authentication (e.g., Authorization: Bearer admin-token)

User Headers: Add standard user authentication (e.g., Authorization: Bearer user-token)

3. Run Tests
Click "Run Vulnerability Tests" to start analysis

Monitor progress as requests are tested with both privilege levels

Review color-coded results in the main table

4. Analyze Results
Red rows: Potential vulnerabilities detected

Green rows: Proper access controls in place

Click any row to view detailed request/response data

🛡️ Vulnerability Detection
The extension identifies access control issues by:

Comparing HTTP status codes between admin and user responses

Analyzing response length differences

Calculating content similarity ratios

Flagging endpoints with inconsistent authorization behavior

🔧 Supported Formats
Format	Description
OpenAPI/Swagger	JSON specifications with full endpoint documentation
Postman Collections	Exported collection files with request definitions
WSDL	XML-based web service descriptions
Burp History	Direct import from proxy traffic
📊 Example Output
text
Method  URL                           Admin Status  User Status  Vulnerability
GET     /api/admin/users             200          403          Safe
POST    /api/admin/delete-user       200          200          VULNERABLE  

🤝 Contributing
Fork the repository

Create a feature branch (git checkout -b feature/enhancement)

Commit changes (git commit -m 'Add new feature')

Push to branch (git push origin feature/enhancement)

Open a Pull Request

📝 License
This project is licensed under the MIT License - see the LICENSE file for details.

⚠️ Disclaimer
This tool is intended for authorized security testing only. Users are responsible for ensuring they have proper permission before testing any applications.

🐛 Issues & Support
Report bugs via GitHub Issues

Feature requests welcome

Join discussions in Issues for support

🏷️ Tags
burp-suite api-security penetration-testing vulnerability-scanner access-control authorization security-testing bug-bounty cybersecurity java
