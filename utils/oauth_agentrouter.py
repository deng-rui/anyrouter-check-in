"""参考 suainam/anyrouter-autolog 的 AgentRouter OAuth 真实重登录流程。"""

from __future__ import annotations

import asyncio
import re
from urllib.parse import parse_qs, urlencode, urlsplit

import httpx

from utils.browser import launch_login_context, load_browser_login_settings, prepare_browser_page
from utils.headers import get_browser_headers

DEFAULT_GITHUB_CLIENT_ID = 'Ov23lidtiR4LeVZvVRNL'
DEFAULT_LINUXDO_CLIENT_ID = 'KZUecGfhhDZMVnv8UtEdhOhf9sNOhqVX'


class AgentRouterOAuthClient:
	"""state 与回调共用站点 HTTP 会话，第三方凭证只交给对应授权站点。"""

	def __init__(self, domain: str):
		self.domain = domain.rstrip('/')

	def fetch_oauth_state(self, client: httpx.Client) -> str:
		response = client.get(f'{self.domain}/api/oauth/state', headers=get_browser_headers(self.domain))
		response.raise_for_status()
		body = response.json()
		if not isinstance(body, dict) or body.get('success') is not True:
			raise RuntimeError('Failed to get OAuth state')
		state = body.get('data')
		if not isinstance(state, str) or not state:
			raise RuntimeError('OAuth state must be a non-empty string')
		return state

	async def authorize(
		self, provider: str, session_token: str, state: str, account_name: str, *, use_proxy: bool
	) -> str:
		"""用浏览器处理第三方授权；截住回跳，交回原 HTTP 会话完成一次登录。"""
		settings = load_browser_login_settings(account_name, 'agentrouter', persist_profile=False)
		context = await launch_login_context(settings, use_proxy=use_proxy)
		try:
			if provider == 'github':
				host = 'https://github.com'
				path = '/login/oauth/authorize'
				cookies = {'user_session': session_token, '__Host-user_session_same_site': session_token, 'logged_in': 'yes'}
				params = {'client_id': DEFAULT_GITHUB_CLIENT_ID, 'state': state, 'scope': 'user:email'}
			elif provider == 'linuxdo':
				host = 'https://connect.linux.do'
				path = '/oauth/authorize'
				cookies = {'_forum_session': session_token}
				params = {'client_id': DEFAULT_LINUXDO_CLIENT_ID, 'state': state, 'response_type': 'code'}
			else:
				raise ValueError(f'Unsupported OAuth provider: {provider}')
			await context.add_cookies([
				{'name': name, 'value': value, 'url': host, 'secure': True, 'httpOnly': True}
				for name, value in cookies.items()
			])
			page = await context.new_page()
			await prepare_browser_page(page)
			captured = asyncio.Event()
			result: dict[str, str] = {}
			callback_origin = urlsplit(self.domain)

			async def capture_callback(route):
				parsed = urlsplit(route.request.url)
				query = parse_qs(parsed.query)
				if (
					(parsed.scheme, parsed.netloc) == (callback_origin.scheme, callback_origin.netloc)
					and parsed.path.rstrip('/') == f'/oauth/{provider}'
				):
					if query.get('state', [''])[0] != state:
						result['error'] = 'OAuth callback state mismatch'
					elif query.get('code', [''])[0]:
						result['code'] = query['code'][0]
					else:
						result['error'] = 'OAuth callback returned no authorization code'
					captured.set()
					await route.fulfill(status=200, content_type='text/plain', body='Authorization received')
				else:
					await route.continue_()

			await page.route(f'{self.domain}/oauth/**', capture_callback)
			await page.goto(f'{host}{path}?{urlencode(params)}', wait_until='domcontentloaded', timeout=settings.wait_timeout_ms)

			async def wait_for_authorization():
				# 授权按钮可能晚于页面加载出现；已授权会话则直接回跳。
				button = page.get_by_role('button', name=re.compile(r'Authorize|授权|同意|Allow', re.I)).first
				while not captured.is_set():
					if await button.is_visible():
						await button.click(timeout=settings.wait_timeout_ms)
						await captured.wait()
					else:
						await asyncio.sleep(0.25)

			try:
				await asyncio.wait_for(wait_for_authorization(), timeout=settings.wait_timeout_ms / 1000)
			except TimeoutError as exc:
				raise RuntimeError(f'{provider} authorization failed; refresh the OAuth session or grant access') from exc
			if 'error' in result:
				raise RuntimeError(result['error'])
			return result['code']
		finally:
			await context.close()

	def callback_login(self, client: httpx.Client, provider: str, code: str, state: str) -> dict:
		response = client.get(
			f'{self.domain}/api/oauth/{provider}',
			params={'code': code, 'state': state, 'mode': 'login'},
			headers=get_browser_headers(self.domain),
		)
		response.raise_for_status()
		body = response.json()
		if not isinstance(body, dict) or body.get('success') is not True:
			message = body.get('message', 'Invalid OAuth response') if isinstance(body, dict) else 'Invalid OAuth response'
			raise RuntimeError(f'OAuth callback failed: {message}')
		profile = body.get('data')
		if not isinstance(profile, dict) or not profile.get('id'):
			raise RuntimeError('OAuth callback returned no user profile')
		return profile
