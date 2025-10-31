from twisted.internet import reactor
from twisted.web.client import Agent
from twisted.web.http_headers import Headers
from xml.dom.minidom import getDOMImplementation
from zope.interface import implementer
from twisted.internet.defer import succeed
from twisted.web.iweb import IBodyProducer
from urllib.parse import urlparse, urlunparse
from ..http_logging import log_http_request

version = "1.0"
DEFAULT_USER_AGENT = "Outlook-iOS-Android/1.0"


def _idna_hostname(host):
	if not host:
		return host
	if isinstance(host, bytes):
		host = host.decode("utf-8")
	try:
		return host.encode("idna").decode("ascii")
	except UnicodeError:
		return host


def _idna_url(url):
	parsed = urlparse(url)
	host = parsed.hostname
	if not host:
		return url
	ascii_host = _idna_hostname(host)
	netloc = ascii_host
	if parsed.port:
		netloc = f"{netloc}:{parsed.port}"
	if parsed.username or parsed.password:
		auth = parsed.username or ""
		if parsed.password:
			auth = f"{auth}:{parsed.password}"
		netloc = f"{auth}@{netloc}"
	updated = parsed._replace(netloc=netloc)
	return urlunparse(updated)


@implementer(IBodyProducer)
class AutoDiscoveryProducer(object):
	def __init__(self, email_address):
		impl = getDOMImplementation()
		newdoc = impl.createDocument(None, "Autodiscover", None)		
		top_element = newdoc.documentElement
		top_element.setAttribute("xmlns", "http://schemas.microsoft.com/exchange/autodiscover/mobilesync/requestschema/2006")
		req_elem = newdoc.createElement('Request')
		top_element.appendChild(req_elem)
		email_elem = newdoc.createElement('EMailAddress')
		req_elem.appendChild(email_elem)
		email_elem.appendChild(newdoc.createTextNode(email_address))
		resp_schema = newdoc.createElement('AcceptableResponseSchema')
		req_elem.appendChild(resp_schema)
		resp_schema.appendChild(newdoc.createTextNode("http://schemas.microsoft.com/exchange/autodiscover/mobilesync/responseschema/2006"))
		self.body = newdoc.toxml("utf-8")
		self.length = len(self.body)

	def startProducing(self, consumer):
		consumer.write(self.body)
		return succeed(None)

	def pauseProducing(self):
		pass

	def stopProducing(self):
		pass

class AutoDiscover:
	"""The AutoDiscover class is used to find EAS servers using only an email address"""
	STATE_INIT = 0
	STATE_XML_REQUEST = 1
	STATE_XML_AUTODISCOVER_REQUEST = 2
	STATE_INSECURE = 3
	STATE_SRV = 4
	STATE_REDIRECT = 5
	LAST_STATE = 6
	AD_REQUESTS = {STATE_XML_REQUEST:"https://%s/autodiscover/autodiscover.xml", 
					STATE_XML_AUTODISCOVER_REQUEST:"https://autodiscover.%s/autodiscover/autodiscover.xml",
					STATE_INSECURE:"http://autodiscover.%s/autodiscover/autodiscover.xml"}

	def __init__(self, email, user_agent=None):
		self.email = email
		self.email_domain = email.split("@")[1]
		self.email_domain_ascii = _idna_hostname(self.email_domain)
		self.agent = Agent(reactor)
		self.state = AutoDiscover.STATE_INIT
		self.redirect_urls = []
		ua = user_agent or DEFAULT_USER_AGENT
		self.user_agent = ua.encode("ascii")
	def _build_headers(self):
		return Headers({b'User-Agent': [self.user_agent]})
	def handle_redirect(self, new_url):
		if new_url in self.redirect_urls:
			raise Exception("AutoDiscover", "Circular redirection")
		self.redirect_urls.append(new_url)
		self.state = AutoDiscover.STATE_REDIRECT
		ascii_url = _idna_url(new_url)
		log_http_request("GET", ascii_url, user=self.email)
		d = self.agent.request(
		    b'GET',
		    ascii_url.encode("ascii"),
		    self._build_headers(),
		    AutoDiscoveryProducer(self.email))
		d.addCallback(self.autodiscover_response)
		d.addErrback(self.autodiscover_error)
		return d
	def autodiscover_response(self, result):
		print("RESPONSE", result, result.code)
		if result.code == 302:
			# TODO: "Redirect responses" validation
			return self.handle_redirect(result.headers.getRawHeaders("location")[0])
		return result
	def autodiscover_error(self, error):
		print("ERROR", error, error.value.reasons[0])
		if self.state < AutoDiscover.LAST_STATE:
			return self.autodiscover()
		raise error
	def autodiscover(self):
		self.state += 1
		if self.state in AutoDiscover.AD_REQUESTS:
			target = AutoDiscover.AD_REQUESTS[self.state] % self.email_domain_ascii
			log_http_request("GET", target, user=self.email)
			body = AutoDiscoveryProducer(self.email)
			d = self.agent.request(
			    b'GET',
			    target.encode("ascii"),
			    self._build_headers(),
			    body)
			d.addCallback(self.autodiscover_response)
			d.addErrback(self.autodiscover_error)
			return d
		else:
			raise Exception("Unsupported state",str(self.state))
