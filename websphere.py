from burp import IBurpExtender
#from burp import ActionListener
from burp import IExtensionHelpers
from burp import IMessageEditorTabFactory
from burp import IMessageEditorTab
import xml.dom.minidom
import urllib2
import urllib
import ssl


class BurpExtender(IBurpExtender, IMessageEditorTabFactory):
	def __init_(self):
		pass

	def registerExtenderCallbacks(self, callback):
		self._helpers = callback.getHelpers()
		callback.setExtensionName('Portlet State Decoder')
		#callback.registerProxyListener(self)
		#callback.registerHttpListener(self)
		print("WebSphere Portal Decoder")
		callback.registerMessageEditorTabFactory(self)
		self.mCalbacks = callback
		return

	def createNewInstance(self, controller, editable):
		tab = WebSphereXMLStateTab(self, controller, editable)
		return tab
		#return XMLInputTab(self, controller, editable)


class WebSphereXMLStateTab(IMessageEditorTab):
	def __init__(self, extender, controller, editable):
		self._extender = extender
		self._editable = editable
		self._controller = controller
		# create an instance of Burp's text editor, to display our deserialized data
		self._txtInput = extender.mCalbacks.createTextEditor()
		self._txtInput.setEditable(editable)
		self._currentMessage = ""
		return

	def getTabCaption(self):
		return "WebSphere State"

	def getUiComponent(self):
		return self._txtInput.getComponent()

	def isEnabled(self, content, isRequest):
		if content and isRequest:
			httpService = self._controller.getHttpService()
			if httpService :
				request = self._extender._helpers.analyzeRequest(self._controller.getHttpService(), content)
				url = request.getUrl().toString()
				return '!ut' in url
		return False

	def setMessage(self, content, isRequest):
		try:
			if not content:
				# clear our display
				self._txtInput.setText("How did this happen?")
				self._txtInput.setEditable(False)
			else:
				reqInfo = self._extender._helpers.analyzeRequest(self._controller.getHttpService(), content)
				url = reqInfo.getUrl()
				path = url.getPath()
				cookie = [h for h in reqInfo.getHeaders() if h.startswith('Cookie:')]				
				if '!ut' in path:
					if 'https' in url.getProtocol() :
						req = '%s://%s/wps/contenthandler?uri=state:%s' % (url.getProtocol(), url.getHost(), urllib.quote(url.toString()))
#						Ignore certificate errors					
						ctx = ssl.create_default_context()
						ctx.check_hostname = False
						ctx.verify_mode = ssl.CERT_NONE
						opener = urllib2.build_opener(urllib2.HTTPSHandler(context=ctx))
					else :
						req = '%s://%s:%d/wps/contenthandler?uri=state:%s' % (url.getProtocol(), url.getHost(), url.getPort(), urllib.quote(url.toString()))
						opener = urllib2.build_opener()

					if cookie:
						opener.addheaders.append(('Cookie', cookie[0].split(': ')[1]))
					print("Making Web Request: %s" % req)
					response = opener.open(req)
					content = response.read()
					content = xml.dom.minidom.parseString(content).toprettyxml()
					if content:
						self._txtInput.setText(content)
						self._currentMessage = content
					else:
						self._currentMessage = ""
		except Exception, e:
			print("Exception! %s - %s" % (e.__class__, e.__doc__))
			print("Message: %s" % e.message)
			print("Reason: %s" % e.reason)
		return

	def getMessage(self):
		print("Called getMessage")
		#not sure what the point of this function is, the only time burp calls it is when you switch out of the tab
		return self._currentMessage

	def isModified(self):
		return self._txtInput.isTextModified()

	def getSelectedData(self):
		return self._txtInput.getSelectedText()
