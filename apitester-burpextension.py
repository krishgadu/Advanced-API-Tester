# BurpAPITester.py - Advanced API Testing Extension for Burp Suite
# Enhanced version with request/response tabs and Repeater integration
from burp import IBurpExtender, ITab, IHttpListener, IContextMenuFactory
from java.awt import BorderLayout, GridLayout, FlowLayout, Color, Font, Dimension
from java.awt.event import ActionListener, MouseAdapter, MouseEvent
from javax.swing import (JPanel, JTable, JScrollPane, JTextArea, JButton, 
                        JTextField, JLabel, JSplitPane, JTabbedPane, 
                        JFileChooser, JOptionPane, JPopupMenu, JMenuItem,
                        SwingUtilities, JFrame, table, DefaultListModel, JList)
from javax.swing.table import DefaultTableModel, TableRowSorter
from javax.swing.filechooser import FileNameExtensionFilter
from java.io import File
from java.net import URL
from java.util import ArrayList
import json
import xml.etree.ElementTree as ET
import re
import threading
import time

class BurpExtender(IBurpExtender, ITab, ActionListener, IContextMenuFactory):
    def registerExtenderCallbacks(self, callbacks):
        """Initialize the extension"""
        self._callbacks = callbacks
        self._helpers = callbacks.getHelpers()
        
        # Set extension name
        callbacks.setExtensionName("Advanced API Tester")
        
        # Initialize data storage
        self.api_requests = []
        self.test_results = []
        
        # Create main UI
        self._create_ui()
        
        # Add tab to Burp Suite
        callbacks.addSuiteTab(self)
        
        # Register context menu factory for importing requests
        callbacks.registerContextMenuFactory(self)
        
        print("Advanced API Tester extension loaded successfully!")

    def _create_ui(self):
        """Create the main user interface"""
        self.main_panel = JPanel(BorderLayout())
        
        # Create top panel with controls
        top_panel = self._create_top_panel()
        self.main_panel.add(top_panel, BorderLayout.NORTH)
        
        # Create main split pane
        main_split = JSplitPane(JSplitPane.VERTICAL_SPLIT)
        
        # Create table panel
        table_panel = self._create_table_panel()
        main_split.setTopComponent(table_panel)
        
        # Create enhanced request/response panel
        request_response_panel = self._create_enhanced_request_response_panel()
        main_split.setBottomComponent(request_response_panel)
        
        main_split.setDividerLocation(300)
        self.main_panel.add(main_split, BorderLayout.CENTER)

    def _create_top_panel(self):
        """Create the top control panel"""
        panel = JPanel(BorderLayout())
        
        # File loading panel
        file_panel = JPanel(FlowLayout(FlowLayout.LEFT))
        
        # Load file button
        self.load_button = JButton("Load API Definition", actionPerformed=self.load_api_definition)
        file_panel.add(self.load_button)
        
        # Import from Burp button
        self.import_button = JButton("Import from Burp History", actionPerformed=self.import_from_burp)
        file_panel.add(self.import_button)
        
        # URL input for remote loading
        file_panel.add(JLabel("Remote URL:"))
        self.url_field = JTextField(30)
        file_panel.add(self.url_field)
        
        self.load_url_button = JButton("Load URL", actionPerformed=self.load_from_url)
        file_panel.add(self.load_url_button)
        
        panel.add(file_panel, BorderLayout.NORTH)
        
        # Headers panel with improved labels
        headers_panel = JPanel(GridLayout(2, 2, 5, 5))
        headers_panel.add(JLabel("Admin Headers (use newlines for multiple):"))
        self.admin_header = JTextArea(2, 30)
        self.admin_header.setText("Authorization: Bearer admin_token")
        self.admin_header.setFont(Font("Monospaced", Font.PLAIN, 12))
        headers_panel.add(JScrollPane(self.admin_header))
        
        headers_panel.add(JLabel("User Headers (use newlines for multiple):"))
        self.user_header = JTextArea(2, 30)
        self.user_header.setText("Authorization: Bearer user_token")
        self.user_header.setFont(Font("Monospaced", Font.PLAIN, 12))
        headers_panel.add(JScrollPane(self.user_header))
        
        panel.add(headers_panel, BorderLayout.CENTER)
        
        # Test button
        test_panel = JPanel(FlowLayout())
        self.test_button = JButton("Run Vulnerability Tests", actionPerformed=self.run_tests)
        self.test_button.setBackground(Color.GREEN)
        self.test_button.setFont(Font("Arial", Font.BOLD, 14))
        test_panel.add(self.test_button)
        
        # Clear button
        self.clear_button = JButton("Clear Results", actionPerformed=self.clear_results)
        test_panel.add(self.clear_button)
        
        panel.add(test_panel, BorderLayout.SOUTH)
        
        return panel

    def _create_table_panel(self):
        """Create the API requests table with color coding"""
        panel = JPanel(BorderLayout())
        panel.add(JLabel("API Requests:"), BorderLayout.NORTH)
        
        # Table columns
        columns = ["Method", "URL", "Admin Status", "User Status", "Length Diff", "Vulnerability", "MIME Type"]
        self.table_model = DefaultTableModel(columns, 0)
        
        # Create custom table with color coding
        self.table = ColorCodedTable(self.table_model, self)
        
        # Enable sorting
        sorter = TableRowSorter(self.table_model)
        self.table.setRowSorter(sorter)
        
        # Add mouse listener for row selection
        self.table.addMouseListener(TableMouseListener(self))
        
        scroll_pane = JScrollPane(self.table)
        scroll_pane.setPreferredSize(Dimension(800, 200))
        panel.add(scroll_pane, BorderLayout.CENTER)
        
        return panel

    def _create_enhanced_request_response_panel(self):
        """Create enhanced request/response viewing panel with separate tabs for requests and responses"""
        main_split = JSplitPane(JSplitPane.HORIZONTAL_SPLIT)
        
        # Left side - Request comparison
        request_panel = JPanel(BorderLayout())
        request_panel.add(JLabel("Request Comparison:"), BorderLayout.NORTH)
        
        self.request_tabs = JTabbedPane()
        
        # Admin request tab with context menu
        self.admin_request_text = JTextArea(15, 40)
        self.admin_request_text.setEditable(False)
        self.admin_request_text.setFont(Font("Monospaced", Font.PLAIN, 12))
        admin_request_scroll = JScrollPane(self.admin_request_text)
        self.admin_request_text.addMouseListener(RequestContextMenuListener(self, "admin"))
        self.request_tabs.addTab("Admin Request", admin_request_scroll)
        
        # User request tab with context menu
        self.user_request_text = JTextArea(15, 40)
        self.user_request_text.setEditable(False)
        self.user_request_text.setFont(Font("Monospaced", Font.PLAIN, 12))
        user_request_scroll = JScrollPane(self.user_request_text)
        self.user_request_text.addMouseListener(RequestContextMenuListener(self, "user"))
        self.request_tabs.addTab("User Request", user_request_scroll)
        
        request_panel.add(self.request_tabs, BorderLayout.CENTER)
        
        # Right side - Response comparison
        response_panel = JPanel(BorderLayout())
        response_panel.add(JLabel("Response Comparison:"), BorderLayout.NORTH)
        
        self.response_tabs = JTabbedPane()
        
        # Admin response tab
        self.admin_response_text = JTextArea(15, 40)
        self.admin_response_text.setEditable(False)
        self.admin_response_text.setFont(Font("Monospaced", Font.PLAIN, 12))
        self.response_tabs.addTab("Admin Response", JScrollPane(self.admin_response_text))
        
        # User response tab
        self.user_response_text = JTextArea(15, 40)
        self.user_response_text.setEditable(False)
        self.user_response_text.setFont(Font("Monospaced", Font.PLAIN, 12))
        self.response_tabs.addTab("User Response", JScrollPane(self.user_response_text))
        
        response_panel.add(self.response_tabs, BorderLayout.CENTER)
        
        main_split.setLeftComponent(request_panel)
        main_split.setRightComponent(response_panel)
        main_split.setDividerLocation(400)
        
        return main_split

    def getTabCaption(self):
        return "API Tester"

    def getUiComponent(self):
        return self.main_panel

    def actionPerformed(self, event):
        """Handle button click events"""
        pass  # Individual buttons have their own actionPerformed handlers

    def send_to_repeater(self, request_text, request_type):
        """Send the displayed request to Burp Repeater"""
        try:
            if not request_text or not request_text.strip():
                JOptionPane.showMessageDialog(self.main_panel, "No request to send")
                return
            
            # Parse the request text to extract URL and build proper request
            lines = request_text.strip().split('\n')
            if not lines:
                return
            
            # Parse request line
            request_line = lines[0]
            parts = request_line.split(' ')
            if len(parts) < 3:
                JOptionPane.showMessageDialog(self.main_panel, "Invalid request format")
                return
            
            method = parts[0]
            path = parts
            
            # Find Host header
            host = None
            for line in lines[1:]:
                if line.lower().startswith('host:'):
                    host = line.split(':', 1)[1].strip()
                    break
            
            if not host:
                JOptionPane.showMessageDialog(self.main_panel, "Host header not found")
                return
            
            # Determine protocol (assume https for now, could be improved)
            use_https = True
            port = 443
            
            # Build HTTP service
            http_service = self._helpers.buildHttpService(host, port, use_https)
            
            # Convert request text to bytes
            request_bytes = self._helpers.stringToBytes(request_text.replace('\n', '\r\n'))
            
            # Send to Repeater
            self._callbacks.sendToRepeater(host, port, use_https, request_bytes, 
                                         "%s Request - %s" % (request_type, method))
            
            JOptionPane.showMessageDialog(self.main_panel, 
                "Request sent to Repeater: %s" % request_type)
            
        except Exception as e:
            JOptionPane.showMessageDialog(self.main_panel, 
                "Error sending to Repeater: %s" % str(e), "Error", JOptionPane.ERROR_MESSAGE)

    def load_api_definition(self, event):
        """Load API definition from file"""
        file_chooser = JFileChooser()
        file_chooser.setFileFilter(FileNameExtensionFilter(
            "API Definition Files", ["json", "xml", "yaml", "yml"]))
        
        result = file_chooser.showOpenDialog(self.main_panel)
        if result == JFileChooser.APPROVE_OPTION:
            file_path = file_chooser.getSelectedFile().getAbsolutePath()
            try:
                self._parse_api_file(file_path)
                JOptionPane.showMessageDialog(self.main_panel, 
                    "Successfully loaded %d API requests" % len(self.api_requests))
                self._update_table()
            except Exception as e:
                JOptionPane.showMessageDialog(self.main_panel, 
                    "Error loading file: %s" % str(e), "Error", JOptionPane.ERROR_MESSAGE)

    def load_from_url(self, event):
        """Load API definition from URL"""
        url_string = self.url_field.getText().strip()
        if not url_string:
            JOptionPane.showMessageDialog(self.main_panel, "Please enter a URL")
            return
        
        try:
            # Create URL object and build HTTP service
            url_obj = URL(url_string)
            
            # Determine if HTTPS
            use_https = url_obj.getProtocol().lower() == "https"
            port = url_obj.getPort()
            if port == -1:
                port = 443 if use_https else 80
            
            # Build HTTP service
            http_service = self._helpers.buildHttpService(
                url_obj.getHost(), port, use_https)
            
            # Build HTTP request
            path = url_obj.getPath()
            if url_obj.getQuery():
                path += "?" + url_obj.getQuery()
            
            request_line = "GET %s HTTP/1.1" % path
            headers = [
                request_line,
                "Host: %s" % url_obj.getHost(),
                "User-Agent: Mozilla/5.0 (compatible; BurpAPITester)",
                "Accept: application/json, application/xml, text/xml",
                "",
                "\n"
            ]
            
            request_bytes = self._helpers.stringToBytes("\r\n".join(headers))
            
            # Make the request
            response = self._callbacks.makeHttpRequest(http_service, request_bytes)
            
            if response is None:
                raise Exception("No response received")
            
            # Analyze response
            response_info = self._helpers.analyzeResponse(response.getResponse())
            body_offset = response_info.getBodyOffset()
            response_body = self._helpers.bytesToString(response.getResponse()[body_offset:])
            
            # Parse the response based on content type
            content_type = self._get_content_type(response_info.getHeaders())
            
            if "json" in content_type.lower():
                self._parse_json_content(response_body, url_string)
            elif "xml" in content_type.lower():
                self._parse_xml_content(response_body)
            else:
                raise Exception("Unsupported content type: %s" % content_type)
            
            JOptionPane.showMessageDialog(self.main_panel, 
                "Successfully loaded %d API requests from URL" % len(self.api_requests))
            self._update_table()
            
        except Exception as e:
            JOptionPane.showMessageDialog(self.main_panel, 
                "Error loading URL: %s" % str(e), "Error", JOptionPane.ERROR_MESSAGE)

    def import_from_burp(self, event):
        """Import requests from Burp Suite HTTP history"""
        try:
            # Get all requests from proxy history
            proxy_history = self._callbacks.getProxyHistory()
            
            count = 0
            for item in proxy_history:
                request_info = self._helpers.analyzeRequest(item)
                url = request_info.getUrl().toString()
                method = request_info.getMethod()
                headers = list(request_info.getHeaders())
                
                # Convert to our internal format
                api_request = {
                    'method': method,
                    'url': url,
                    'headers': headers[1:],  # Skip the request line
                    'body': None,
                    'source': 'burp_history'
                }
                
                # Get body if present
                body_offset = request_info.getBodyOffset()
                request_bytes = item.getRequest()
                if body_offset < len(request_bytes):
                    api_request['body'] = self._helpers.bytesToString(request_bytes[body_offset:])
                
                self.api_requests.append(api_request)
                count += 1
            
            JOptionPane.showMessageDialog(self.main_panel, 
                "Successfully imported %d requests from Burp history" % count)
            self._update_table()
            
        except Exception as e:
            JOptionPane.showMessageDialog(self.main_panel, 
                "Error importing from Burp: %s" % str(e), "Error", JOptionPane.ERROR_MESSAGE)

    def createMenuItems(self, context_menu_invocation):
        """Create context menu items for importing selected requests"""
        menu_items = []
        
        # Add menu item to import selected requests
        import_item = JMenuItem("Import to API Tester")
        import_item.addActionListener(ImportActionListener(self, context_menu_invocation))
        menu_items.append(import_item)
        
        return menu_items

    def import_selected_requests(self, context_menu_invocation):
        """Import selected requests from context menu"""
        try:
            selected_messages = context_menu_invocation.getSelectedMessages()
            count = 0
            
            for message in selected_messages:
                request_info = self._helpers.analyzeRequest(message)
                url = request_info.getUrl().toString()
                method = request_info.getMethod()
                headers = list(request_info.getHeaders())
                
                # Convert to our internal format
                api_request = {
                    'method': method,
                    'url': url,
                    'headers': headers[1:],  # Skip the request line
                    'body': None,
                    'source': 'burp_selected'
                }
                
                # Get body if present
                body_offset = request_info.getBodyOffset()
                request_bytes = message.getRequest()
                if body_offset < len(request_bytes):
                    api_request['body'] = self._helpers.bytesToString(request_bytes[body_offset:])
                
                self.api_requests.append(api_request)
                count += 1
            
            SwingUtilities.invokeLater(lambda: self._update_table())
            SwingUtilities.invokeLater(lambda: JOptionPane.showMessageDialog(
                self.main_panel, "Successfully imported %d selected requests" % count))
            
        except Exception as e:
            SwingUtilities.invokeLater(lambda: JOptionPane.showMessageDialog(
                self.main_panel, "Error importing selected requests: %s" % str(e), 
                "Error", JOptionPane.ERROR_MESSAGE))

    def run_tests(self, event):
        """Run vulnerability tests on all API requests"""
        if not self.api_requests:
            JOptionPane.showMessageDialog(self.main_panel, "No API requests loaded")
            return
        
        admin_header = self.admin_header.getText().strip()
        user_header = self.user_header.getText().strip()
        
        if not admin_header or not user_header:
            JOptionPane.showMessageDialog(self.main_panel, "Please specify both admin and user headers")
            return
        
        # Run tests in background thread
        test_thread = threading.Thread(target=self._run_tests_background, 
                                      args=(admin_header, user_header))
        test_thread.daemon = True
        test_thread.start()

    def _run_tests_background(self, admin_header, user_header):
        """Run tests in background thread"""
        try:
            self.test_results = []
            
            for i, api_request in enumerate(self.api_requests):
                # Update UI to show progress
                SwingUtilities.invokeLater(lambda idx=i: self._update_test_progress(idx))
                
                result = self._test_single_request(api_request, admin_header, user_header)
                self.test_results.append(result)
            
            # Update table with results
            SwingUtilities.invokeLater(lambda: self._update_table_with_results())
            SwingUtilities.invokeLater(lambda: JOptionPane.showMessageDialog(
                self.main_panel, "Testing completed! Found %d potential vulnerabilities." % 
                sum(1 for r in self.test_results if r.get('vulnerable', False))))
            
        except Exception as e:
            SwingUtilities.invokeLater(lambda: JOptionPane.showMessageDialog(
                self.main_panel, "Error during testing: %s" % str(e), 
                "Error", JOptionPane.ERROR_MESSAGE))

    def _parse_multiple_headers(self, header_input):
        """Parse multiple headers from input (separated by newlines)"""
        headers = {}
        
        if not header_input:
            return headers
        
        # Split by newlines
        header_lines = header_input.split('\n')
        
        for line in header_lines:
            line = line.strip()
            if line and ':' in line:
                name, value = line.split(':', 1)
                headers[name.strip().lower()] = {
                    'name': name.strip(),
                    'value': value.strip()
                }
        
        return headers

    def _test_single_request(self, api_request, admin_header, user_header):
        """Test a single API request with both headers"""
        result = {
            'admin_request': None,
            'user_request': None,
            'admin_response': None,
            'user_response': None,
            'admin_status': 0,
            'user_status': 0,
            'length_diff': 0,
            'vulnerable': False,
            'mime_type': ''
        }
        
        try:
            url_string = api_request['url']
            method = api_request['method']
            
            # Parse URL properly
            url_obj = URL(url_string)
            
            # Determine if HTTPS
            use_https = url_obj.getProtocol().lower() == "https"
            port = url_obj.getPort()
            if port == -1:
                port = 443 if use_https else 80
            
            # Build HTTP service
            http_service = self._helpers.buildHttpService(
                url_obj.getHost(), port, use_https)
            
            # Test with admin header
            admin_request_bytes = self._build_http_request(url_obj, method, admin_header, 
                                                         api_request.get('body'), 
                                                         api_request.get('headers', []))
            
            # Store the admin request text for display
            result['admin_request'] = self._helpers.bytesToString(admin_request_bytes)
            
            admin_response = self._callbacks.makeHttpRequest(http_service, admin_request_bytes)
            
            # Test with user header
            user_request_bytes = self._build_http_request(url_obj, method, user_header, 
                                                        api_request.get('body'),
                                                        api_request.get('headers', []))
            
            # Store the user request text for display
            result['user_request'] = self._helpers.bytesToString(user_request_bytes)
            
            user_response = self._callbacks.makeHttpRequest(http_service, user_request_bytes)
            
            # Analyze responses
            if admin_response and admin_response.getResponse():
                admin_info = self._helpers.analyzeResponse(admin_response.getResponse())
                result['admin_status'] = admin_info.getStatusCode()
                result['admin_response'] = self._helpers.bytesToString(admin_response.getResponse())
                
                # Get MIME type
                admin_headers = admin_info.getHeaders()
                for header in admin_headers:
                    if header.lower().startswith("content-type:"):
                        result['mime_type'] = header.split(":", 1)[1].strip()
                        break
            
            if user_response and user_response.getResponse():
                user_info = self._helpers.analyzeResponse(user_response.getResponse())
                result['user_status'] = user_info.getStatusCode()
                result['user_response'] = self._helpers.bytesToString(user_response.getResponse())
                
                # Calculate response length difference
                if admin_response and admin_response.getResponse():
                    admin_length = len(admin_response.getResponse())
                    user_length = len(user_response.getResponse())
                    result['length_diff'] = abs(admin_length - user_length)
                    
                    # Determine vulnerability
                    result['vulnerable'] = self._is_vulnerable(admin_info, user_info, 
                                                            result['admin_response'], 
                                                            result['user_response'])
            
        except Exception as e:
            print("Error testing request %s: %s" % (api_request.get('url', 'unknown'), str(e)))
        
        return result

    def _build_http_request(self, url_obj, method, auth_header, body, original_headers=None):
        """Build HTTP request preserving original headers and updating auth headers"""
        try:
            path = url_obj.getPath()
            if url_obj.getQuery():
                path += "?" + url_obj.getQuery()
            
            request_line = "%s %s HTTP/1.1" % (method, path)
            
            # Parse multiple auth headers
            auth_headers = self._parse_multiple_headers(auth_header)
            
            # Start with original headers
            headers_dict = {}
            
            # Add original headers first (skip any request lines)
            if original_headers:
                for header in original_headers:
                    header = header.strip()
                    if header and ":" in header and not header.startswith(("GET ", "POST ", "PUT ", "DELETE ", "PATCH ", "HEAD ", "OPTIONS ")):
                        header_name, header_value = header.split(":", 1)
                        headers_dict[header_name.strip().lower()] = header_name.strip() + ":" + header_value
            
            # Ensure essential headers
            if 'host' not in headers_dict:
                headers_dict['host'] = "Host: %s" % url_obj.getHost()
            
            if 'user-agent' not in headers_dict:
                headers_dict['user-agent'] = "User-Agent: Mozilla/5.0 (compatible; BurpAPITester)"
            
            # Update with auth headers (this will override any existing ones)
            for header_key, header_info in auth_headers.items():
                headers_dict[header_key] = "%s: %s" % (header_info['name'], header_info['value'])
            
            # Handle body-related headers
            if body:
                body_bytes = body.encode('utf-8') if isinstance(body, unicode) else body
                headers_dict['content-length'] = "Content-Length: %d" % len(body_bytes)
                
                if 'content-type' not in headers_dict:
                    headers_dict['content-type'] = "Content-Type: application/json"
            else:
                headers_dict.pop('content-length', None)
            
            # Build final headers
            final_headers = [request_line]
            
            # Host header first
            if 'host' in headers_dict:
                final_headers.append(headers_dict.pop('host'))
            
            # Add remaining headers
            for header_value in headers_dict.values():
                final_headers.append(header_value)
            
            final_headers.append("")
            
            # Build complete request
            request_string = "\r\n".join(final_headers)
            if body:
                request_string += "\r\n" + body
            
            return self._helpers.stringToBytes(request_string)
            
        except Exception as e:
            print("Error building request: %s" % str(e))
            return None

    def _is_vulnerable(self, admin_info, user_info, admin_response, user_response):
        """Determine if the request shows potential vulnerability"""
        # Compare status codes
        if admin_info.getStatusCode() != user_info.getStatusCode():
            return False  # Different status codes suggest different access levels
        
        # Compare response lengths
        length_diff = abs(len(admin_response) - len(user_response))
        if length_diff > 100:  # Significant difference
            return False
        
        # Compare response bodies (simplified)
        admin_body_start = admin_info.getBodyOffset()
        user_body_start = user_info.getBodyOffset()
        
        admin_body = admin_response[admin_body_start:admin_body_start+500] if admin_body_start < len(admin_response) else ""
        user_body = user_response[user_body_start:user_body_start+500] if user_body_start < len(user_response) else ""
        
        # If responses are very similar, might be vulnerable
        similarity = self._calculate_similarity(admin_body, user_body)
        return similarity > 0.9  # 90% similar suggests potential access control issue

    def _calculate_similarity(self, text1, text2):
        """Calculate simple similarity between two texts"""
        if not text1 and not text2:
            return 1.0
        if not text1 or not text2:
            return 0.0
        
        # Simple character-based similarity
        common_chars = sum(1 for a, b in zip(text1, text2) if a == b)
        return float(common_chars) / max(len(text1), len(text2))

    def clear_results(self, event):
        """Clear all results and data"""
        self.api_requests = []
        self.test_results = []
        self._update_table()
        self.admin_request_text.setText("")
        self.user_request_text.setText("")
        self.admin_response_text.setText("")
        self.user_response_text.setText("")
        JOptionPane.showMessageDialog(self.main_panel, "Results cleared")

    def _update_table(self):
        """Update the main table with API requests"""
        self.table_model.setRowCount(0)
        
        for i, request in enumerate(self.api_requests):
            row_data = [
                request.get('method', 'GET'),
                request.get('url', ''),
                '',  # Admin status - will be filled after testing
                '',  # User status
                '',  # Length diff
                '',  # Vulnerability status
                ''   # MIME type
            ]
            self.table_model.addRow(row_data)

    def _update_table_with_results(self):
        """Update table with test results"""
        for i, result in enumerate(self.test_results):
            if i < self.table_model.getRowCount():
                self.table_model.setValueAt(str(result.get('admin_status', '')), i, 2)
                self.table_model.setValueAt(str(result.get('user_status', '')), i, 3)
                self.table_model.setValueAt(str(result.get('length_diff', '')), i, 4)
                
                vulnerability_status = "VULNERABLE" if result.get('vulnerable', False) else "Safe"
                self.table_model.setValueAt(vulnerability_status, i, 5)
                self.table_model.setValueAt(result.get('mime_type', ''), i, 6)
        
        # Force table repaint to show colors
        self.table.repaint()

    def _update_test_progress(self, current_index):
        """Update UI to show testing progress"""
        self.test_button.setText("Testing... (%d/%d)" % (current_index + 1, len(self.api_requests)))

    def show_request_details(self, row_index):
        """Show details for selected table row with enhanced request/response display"""
        if row_index >= 0 and row_index < len(self.api_requests):
            request = self.api_requests[row_index]
            
            # Show request details if test results are available
            if row_index < len(self.test_results):
                result = self.test_results[row_index]
                
                # Show admin request
                admin_request = result.get('admin_request', '')
                if admin_request:
                    self.admin_request_text.setText(admin_request)
                else:
                    # Fallback to building request display
                    admin_request_display = self._build_request_display(request, "admin")
                    self.admin_request_text.setText(admin_request_display)
                
                # Show user request
                user_request = result.get('user_request', '')
                if user_request:
                    self.user_request_text.setText(user_request)
                else:
                    # Fallback to building request display
                    user_request_display = self._build_request_display(request, "user")
                    self.user_request_text.setText(user_request_display)
                
                # Show responses
                self.admin_response_text.setText(result.get('admin_response', ''))
                self.user_response_text.setText(result.get('user_response', ''))
            else:
                # Show basic request info if no test results yet
                self.admin_request_text.setText(self._build_request_display(request, "admin"))
                self.user_request_text.setText(self._build_request_display(request, "user"))
                self.admin_response_text.setText("No response data available")
                self.user_response_text.setText("No response data available")

    def _build_request_display(self, request, role):
        """Build request display text for the given role"""
        try:
            method = request.get('method', 'GET')
            url = request.get('url', '')
            
            # Parse URL for display
            url_obj = URL(url)
            path = url_obj.getPath()
            if url_obj.getQuery():
                path += "?" + url_obj.getQuery()
            
            request_text = "%s %s HTTP/1.1\n" % (method, path)
            request_text += "Host: %s\n" % url_obj.getHost()
            
            # Add original headers
            if request.get('headers'):
                for header in request.get('headers', []):
                    request_text += header + "\n"
            
            # Add role-specific auth header
            auth_header = self.admin_header.getText().strip() if role == "admin" else self.user_header.getText().strip()
            if auth_header:
                for auth_line in auth_header.split('\n'):
                    if auth_line.strip():
                        request_text += auth_line.strip() + "\n"
            
            # Add body if present
            if request.get('body'):
                request_text += "\n" + request.get('body')
            
            return request_text
        except Exception as e:
            return "Error building request display: %s" % str(e)

    # ... (keeping all the existing parsing methods unchanged)
    def _parse_api_file(self, file_path):
        """Parse API definition file"""
        try:
            with open(file_path, 'r') as f:
                content = f.read()
            
            file_ext = file_path.lower().split('.')[-1]
            
            if file_ext == 'json':
                self._parse_json_content(content, file_path)
            elif file_ext in ['xml', 'wsdl']:
                self._parse_xml_content(content)
            elif file_ext in ['yaml', 'yml']:
                self._parse_yaml_content(content)
            else:
                raise Exception("Unsupported file type: %s" % file_ext)
        
        except Exception as e:
            raise Exception("Error parsing file: %s" % str(e))

    def _parse_json_content(self, content, source_info=""):
        """Parse JSON content (Postman collection or OpenAPI)"""
        try:
            data = json.loads(content)
            
            # Check if it's a Postman collection
            if 'info' in data and 'item' in data:
                self._parse_postman_collection(data)
            # Check if it's OpenAPI/Swagger
            elif 'openapi' in data or 'swagger' in data:
                self._parse_openapi_spec(data)
            else:
                raise Exception("Unknown JSON format")
        
        except Exception as e:
            raise Exception("Error parsing JSON: %s" % str(e))

    def _parse_postman_collection(self, collection):
        """Parse Postman collection"""
        def extract_requests(items, base_url=""):
            for item in items:
                if 'request' in item:
                    request = item['request']
                    method = request.get('method', 'GET')
                    
                    # Build URL
                    url_obj = request.get('url', {})
                    if isinstance(url_obj, dict):
                        raw_url = url_obj.get('raw', '')
                        if not raw_url and 'host' in url_obj:
                            host = ''.join(url_obj['host']) if isinstance(url_obj['host'], list) else url_obj['host']
                            path = '/'.join(url_obj.get('path', []))
                            raw_url = "http://%s/%s" % (host, path)
                        url = raw_url
                    else:
                        url = str(url_obj)
                    
                    # Extract headers
                    headers = []
                    for header in request.get('header', []):
                        if not header.get('disabled', False):
                            headers.append("%s: %s" % (header.get('key', ''), header.get('value', '')))
                    
                    # Extract body
                    body = None
                    body_obj = request.get('body')
                    if body_obj:
                        if body_obj.get('mode') == 'raw':
                            body = body_obj.get('raw', '')
                    
                    api_request = {
                        'method': method,
                        'url': url,
                        'headers': headers,
                        'body': body,
                        'source': 'postman'
                    }
                    self.api_requests.append(api_request)
                
                # Handle nested items
                if 'item' in item:
                    extract_requests(item['item'], base_url)
        
        extract_requests(collection.get('item', []))

    def _parse_openapi_spec(self, spec):
        """Parse OpenAPI/Swagger specification"""
        base_url = ""
        
        # Get base URL
        if 'servers' in spec and spec['servers']:
            base_url = spec['servers'][0].get('url', '')
        elif 'host' in spec:
            protocol = 'https' if spec.get('schemes', ['http'])[0] == 'https' else 'http'
            base_path = spec.get('basePath', '')
            base_url = "%s://%s%s" % (protocol, spec['host'], base_path)
        
        # Parse paths
        for path, methods in spec.get('paths', {}).items():
            for method, operation in methods.items():
                if method.upper() in ['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'HEAD', 'OPTIONS']:
                    full_url = base_url + path
                    
                    api_request = {
                        'method': method.upper(),
                        'url': full_url,
                        'headers': ['Content-Type: application/json'],
                        'body': None,
                        'source': 'openapi'
                    }
                    self.api_requests.append(api_request)

    def _parse_xml_content(self, content):
        """Parse XML content (WSDL)"""
        try:
            root = ET.fromstring(content)
            
            # Simple WSDL parsing - extract service operations
            namespaces = {'wsdl': 'http://schemas.xmlsoap.org/wsdl/'}
            
            operations = root.findall('.//wsdl:operation', namespaces)
            for operation in operations:
                name = operation.get('name', 'unknown')
                
                api_request = {
                    'method': 'POST',
                    'url': 'http://example.com/soap',  # Placeholder
                    'headers': ['Content-Type: text/xml', 'SOAPAction: "%s"' % name],
                    'body': '<?xml version="1.0"?><soap:Envelope></soap:Envelope>',
                    'source': 'wsdl'
                }
                self.api_requests.append(api_request)
        
        except Exception as e:
            raise Exception("Error parsing XML: %s" % str(e))

    def _parse_yaml_content(self, content):
        """Parse YAML content (OpenAPI)"""
        # Simplified YAML parsing - would need proper YAML library
        raise Exception("YAML parsing not implemented - please use JSON format")

    def _get_content_type(self, headers):
        """Extract content type from headers"""
        for header in headers:
            if header.lower().startswith("content-type:"):
                return header.split(":", 1)[1].strip()
        return "text/plain"


# Custom JTable class with color coding capability
class ColorCodedTable(JTable):
    def __init__(self, table_model, parent_extender):
        JTable.__init__(self, table_model)
        self._extender = parent_extender
    
    def prepareRenderer(self, renderer, row, col):
        """Override to apply custom colors based on vulnerability status"""
        comp = JTable.prepareRenderer(self, renderer, row, col)
        
        # Get the actual value from the model (handle sorting)
        model_row = self.convertRowIndexToModel(row)
        
        # Apply color coding for the Vulnerability column (column 5)
        if col == 5:  # Vulnerability Status column
            value = self.getModel().getValueAt(model_row, col)
            if value == "VULNERABLE":
                comp.setBackground(Color(220, 20, 60))  # Crimson red for vulnerable
                comp.setForeground(Color.WHITE)
            elif value == "Safe":
                comp.setBackground(Color(34, 139, 34))  # Forest green for safe
                comp.setForeground(Color.WHITE)
            else:
                # Default colors for untested entries
                comp.setBackground(Color.WHITE)
                comp.setForeground(Color.BLACK)
        else:
            # For other columns, check if this row is vulnerable to apply row highlighting
            vulnerability_status = self.getModel().getValueAt(model_row, 5)
            if vulnerability_status == "VULNERABLE":
                comp.setBackground(Color(255, 240, 240))  # Light red background for entire row
                comp.setForeground(Color.BLACK)
            elif vulnerability_status == "Safe":
                comp.setBackground(Color(240, 255, 240))  # Light green background for entire row
                comp.setForeground(Color.BLACK)
            else:
                comp.setBackground(Color.WHITE)
                comp.setForeground(Color.BLACK)
        
        return comp


# Helper classes
class TableMouseListener(MouseAdapter):
    def __init__(self, parent):
        self.parent = parent
    
    def mouseClicked(self, event):
        if event.getClickCount() == 1:
            row = self.parent.table.getSelectedRow()
            if row >= 0:
                # Convert view row to model row (for sorting)
                model_row = self.parent.table.convertRowIndexToModel(row)
                self.parent.show_request_details(model_row)


class RequestContextMenuListener(MouseAdapter):
    def __init__(self, parent, request_type):
        self.parent = parent
        self.request_type = request_type
    
    def mousePressed(self, event):
        if event.isPopupTrigger():
            self._show_popup(event)
    
    def mouseReleased(self, event):
        if event.isPopupTrigger():
            self._show_popup(event)
    
    def _show_popup(self, event):
        popup = JPopupMenu()
        
        send_to_repeater_item = JMenuItem("Send to Repeater")
        send_to_repeater_item.addActionListener(SendToRepeaterActionListener(self.parent, self.request_type))
        popup.add(send_to_repeater_item)
        
        popup.show(event.getComponent(), event.getX(), event.getY())


class SendToRepeaterActionListener(ActionListener):
    def __init__(self, parent, request_type):
        self.parent = parent
        self.request_type = request_type
    
    def actionPerformed(self, event):
        if self.request_type == "admin":
            request_text = self.parent.admin_request_text.getText()
        else:
            request_text = self.parent.user_request_text.getText()
        
        self.parent.send_to_repeater(request_text, self.request_type.capitalize())


class ImportActionListener(ActionListener):
    def __init__(self, parent, context_menu_invocation):
        self.parent = parent
        self.context_menu_invocation = context_menu_invocation
    
    def actionPerformed(self, event):
        self.parent.import_selected_requests(self.context_menu_invocation)
