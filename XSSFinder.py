from burp import IBurpExtender, IScannerCheck, IScanIssue, IParameter, ITab, IHttpRequestResponseWithMarkers
from java.io import PrintWriter
from java.net import URL
from javax.swing import JPanel, JLabel, JTextField, JButton, BoxLayout, JScrollPane, JList, DefaultListModel, \
    JOptionPane
from array import array
from java.util import ArrayList


class BurpExtender(IBurpExtender, IScannerCheck, ITab):
    def registerExtenderCallbacks(self, callbacks):
        self._callbacks = callbacks
        self._helpers = callbacks.getHelpers()
        self._stdout = PrintWriter(callbacks.getStdout(), True)
        self._stderr = PrintWriter(callbacks.getStderr(), True)
        callbacks.setExtensionName("XSS Finder")
        callbacks.registerScannerCheck(self)

        # Init default config
        self.payloads = {
            "zzzzhappi\"><img src=x": "Certain",
            "zzzzhappi\"": "Firm",
            "zzzzhappi": "Tentative"
        }
        self.exclusions = []

        # Create configuration tab
        self.config_panel = ConfigPanel(self)
        callbacks.addSuiteTab(self)

        self._stdout.println("XSS Scanner Extension Loaded")

    def getTabCaption(self):
        return "XSS Finder"

    def getUiComponent(self):
        return self.config_panel
    
    def doActiveScan(self, baseRequestResponse, insertionPoint):
        return None

    def doPassiveScan(self, baseRequestResponse):
        issues = []

        request = baseRequestResponse.getRequest()
        analyzedRequest = self._helpers.analyzeRequest(request)

        response = baseRequestResponse.getResponse()
        analyzedResponse = self._helpers.analyzeResponse(response)

        if analyzedResponse.getStatusCode() in [301, 302]:
            return issues

        headers = analyzedResponse.getHeaders()

        # Step 1 & 2: Check Content-Type
        content_type_allowed = True
        for header in headers:
            if header.lower().startswith("content-type:"):
                if "application/x-javascript" in header or "application/json" in header:
                    content_type_allowed = False
                break

        if not content_type_allowed:
            return issues

        # Step 3: Check if any parameter is reflected in the response
        params = analyzedRequest.getParameters()
        for param in params:
            if param.getType() == IParameter.PARAM_COOKIE:  # ignore XSS in cookie for now
                continue
            elif param.getName() in self.exclusions:
                continue
            elif param.getType() not in [IParameter.PARAM_URL, IParameter.PARAM_BODY]:
                # Ignorer les types de paramètres non supportés
                continue
            # Step 4: try payloads
            for payload, confidence in self.get_xss_payloads().items():
                new_req = self._helpers.updateParameter(request, self._helpers.buildParameter(
                    param.getName(),
                    self._helpers.urlEncode(payload),
                    param.getType()
                ))
                attack = self._callbacks.makeHttpRequest(baseRequestResponse.getHttpService(), new_req)
                response_str = self._helpers.bytesToString(attack.getResponse())
                if payload in response_str:
                    # Highlight the payload in the request
                    request_offsets = self.find_payload_offsets(new_req, payload)
                    # Highlight the payload in the response
                    response_offsets = self.find_payload_offsets(attack.getResponse(), payload)

                    attackWithMarkers = self._callbacks.applyMarkers(
                        attack,
                        self.convert_offsets_to_list(request_offsets),
                        self.convert_offsets_to_list(response_offsets)
                    )

                    title = "RXSS in '{}' parameter '{}' on '{}'".format(
                        "GET" if param.getType() == IParameter.PARAM_URL else "POST",
                        param.getName(),
                        self._helpers.analyzeRequest(baseRequestResponse).getUrl()
                    )
                    self._stdout.println(title)
                    issues.append(
                        CustomScanIssue(
                            url=self._helpers.analyzeRequest(baseRequestResponse).getUrl(),
                            name=title,
                            detail="Payload found: {}\nTrust level: {}".format(payload, confidence),
                            confidence=confidence,
                            http_messages=[attackWithMarkers],
                            http_service=baseRequestResponse.getHttpService(),
                        )
                    )
                    break  # stop on first successful payload
        return issues

    def find_payload_offsets(self, data, payload):
        data_str = self._helpers.bytesToString(data)
        start = data_str.find(payload)
        if start == -1:
            return []
        end = start + len(payload)
        return [(start, end)]

    @staticmethod
    def convert_offsets_to_list(offsets):
        markers = ArrayList()
        for start, end in offsets:
            markers.add(array('i', [start, end]))
        return markers

    def get_xss_payloads(self):
        return self.payloads

    def set_config(self, payloads, exclusions):
        self.payloads = payloads
        self.exclusions = exclusions

    def consolidateDuplicateIssues(self, existingIssue, newIssue):
        return -1


class CustomScanIssue(IScanIssue):
    def __init__(self, url, name, detail, confidence, http_messages, http_service):
        self._url = url
        self._name = name
        self._detail = detail
        self._confidence = confidence
        self._http_messages = http_messages
        self._http_service = http_service

    def getUrl(self):
        return self._url

    def getIssueName(self):
        return self._name

    def getIssueType(self):
        return 0

    def getSeverity(self):
        return "High"

    def getConfidence(self):
        return self._confidence

    def getIssueBackground(self):
        return ""

    def getRemediationBackground(self):
        return ""

    def getIssueDetail(self):
        return self._detail

    def getRemediationDetail(self):
        return ""

    def getHttpMessages(self):
        return self._http_messages

    def getHttpService(self):
        return self._http_service


class ConfigPanel(JPanel):
    def __init__(self, extender):
        self.extender = extender
        self.setLayout(BoxLayout(self, BoxLayout.Y_AXIS))

        # Section pour les payloads
        self.add(JLabel("Payloads:"))
        self.payloads_model = DefaultListModel()
        for payload, trust in self.extender.payloads.items():
            self.payloads_model.addElement("{} : {}".format(payload, trust))
        self.payloads_list = JList(self.payloads_model)
        self.add(JScrollPane(self.payloads_list))
        self.add(self.create_button_panel(self.payloads_model, "payload"))

        # Section pour les exclusions
        self.add(JLabel("Parameters to exclude:"))
        self.exclusions_model = DefaultListModel()
        for exclusion in self.extender.exclusions:
            self.exclusions_model.addElement(exclusion)
        self.exclusions_list = JList(self.exclusions_model)
        self.add(JScrollPane(self.exclusions_list))
        self.add(self.create_button_panel(self.exclusions_model, "exclusion"))

        # Bouton de sauvegarde
        save_button = JButton("Save", actionPerformed=self.save_config)
        self.add(save_button)

    def create_button_panel(self, model, name):
        panel = JPanel()
        panel.setLayout(BoxLayout(panel, BoxLayout.X_AXIS))

        if name == "payload":
            add_button = JButton("Add", actionPerformed=lambda event: self.add_payload_item(model))
        else:
            add_button = JButton("Add", actionPerformed=lambda event: self.add_exclusion_item(model))

        remove_button = JButton("Remove", actionPerformed=lambda event: self.remove_item(model))
        up_button = JButton("Up", actionPerformed=lambda event: self.move_item(model, -1))
        down_button = JButton("Down", actionPerformed=lambda event: self.move_item(model, 1))

        panel.add(add_button)
        panel.add(remove_button)
        panel.add(up_button)
        panel.add(down_button)

        return panel

    def add_payload_item(self, model):
        input_panel = JPanel()
        input_panel.setLayout(BoxLayout(input_panel, BoxLayout.Y_AXIS))

        new_payload = JTextField(20)
        new_trust = JTextField(20)

        input_panel.add(JLabel("New Payload:"))
        input_panel.add(new_payload)

        input_panel.add(JLabel("Trust Level (e.g., High, Medium, Low):"))
        input_panel.add(new_trust)

        result = JOptionPane.showConfirmDialog(self, input_panel, "Add payload", JOptionPane.OK_CANCEL_OPTION)
        if result == JOptionPane.OK_OPTION:
            model.addElement("{} : {}".format(new_payload.getText(), new_trust.getText()))

    def add_exclusion_item(self, model):
        new_exclusion = JTextField(20)
        result = JOptionPane.showConfirmDialog(self, new_exclusion, "Add exclusion", JOptionPane.OK_CANCEL_OPTION)
        if result == JOptionPane.OK_OPTION:
            model.addElement(new_exclusion.getText())

    def remove_item(self, model):
        selected_index = self.payloads_list.getSelectedIndex()
        if selected_index != -1:
            model.remove(selected_index)

    def move_item(self, model, direction):
        selected_index = self.payloads_list.getSelectedIndex()
        if selected_index != -1:
            new_index = selected_index + direction
            if 0 <= new_index < model.getSize():
                element = model.getElementAt(selected_index)
                model.remove(selected_index)
                model.add(new_index, element)

    def save_config(self, event):
        payloads = {}
        for i in range(self.payloads_model.getSize()):
            item = self.payloads_model.getElementAt(i)
            payload, trust = item.split(" : ")
            payloads[payload] = trust
        exclusions = [self.exclusions_model.getElementAt(i) for i in range(self.exclusions_model.getSize())]
        self.extender.set_config(payloads, exclusions)
