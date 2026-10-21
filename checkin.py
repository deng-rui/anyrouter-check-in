#!/usr/bin/env python3
"""
AnyRouter.top 自动签到脚本
"""

import asyncio
import hashlib
import json
import os
import sys
from datetime import datetime
from urllib.parse import urlsplit

if hasattr(sys.stdout, 'reconfigure'):
	sys.stdout.reconfigure(line_buffering=True)
if hasattr(sys.stderr, 'reconfigure'):
	sys.stderr.reconfigure(line_buffering=True)

import httpx
from cloakbrowser import launch_async
from dotenv import load_dotenv

from utils.browser import (
	BrowserLoginResult,
	has_session_cookie,
	is_logged_in,
	launch_login_context,
	load_browser_login_settings,
	login_with_email_form,
	navigate_login_page,
	prepare_browser_page,
	save_login_screenshot,
	take_pending_screenshots,
	verify_browser_login,
	wait_for_waf_ready,
)
from utils.config import AccountConfig, AppConfig, load_accounts_config
from utils.debug import debug_print, is_debug_enabled
from utils.headers import get_browser_headers
from utils.notify import notify
from utils.oauth_agentrouter import AgentRouterOAuthClient
from utils.proxy import get_playwright_proxy, get_proxy_server

load_dotenv()

BALANCE_HASH_FILE = 'balance_hash.txt'


def load_balance_hash():
	"""加载余额hash"""
	try:
		if os.path.exists(BALANCE_HASH_FILE):
			with open(BALANCE_HASH_FILE, 'r', encoding='utf-8') as f:
				return f.read().strip()
	except Exception:  # nosec B110
		pass
	return None


def save_balance_hash(balance_hash):
	"""保存余额hash"""
	try:
		with open(BALANCE_HASH_FILE, 'w', encoding='utf-8') as f:
			f.write(balance_hash)
	except Exception as e:
		print(f'Warning: Failed to save balance hash: {e}')


def generate_balance_hash(balances):
	"""生成余额数据的hash"""
	simple_balances = (
		{k: {'quota': v.get('quota'), 'used': v.get('used')} for k, v in balances.items()} if balances else {}
	)
	balance_json = json.dumps(simple_balances, sort_keys=True, separators=(',', ':'))
	return hashlib.sha256(balance_json.encode('utf-8')).hexdigest()[:16]


def parse_cookies(cookies_data):
	"""解析 cookies 数据"""
	if isinstance(cookies_data, dict):
		return cookies_data

	if isinstance(cookies_data, str):
		cookies_dict = {}
		for cookie in cookies_data.split(';'):
			if '=' in cookie:
				key, value = cookie.strip().split('=', 1)
				cookies_dict[key] = value
		return cookies_dict
	return {}


def get_site_cookies(cookies_data) -> dict:
	"""第三方 OAuth 凭证不能随站点请求或账号密码登录发送给 AgentRouter。"""
	return {
		name: value
		for name, value in parse_cookies(cookies_data).items()
		if name not in {'user_session', '__Host-user_session_same_site', 'logged_in', '_forum_session', 'github_session', 'linuxdo_session'}
	}


def set_site_cookies(client: httpx.Client, cookies: dict, domain: str) -> None:
	"""绑定站点域名，避免 OAuth 更新 session 后仍发送同名的无域 Cookie。"""
	host = urlsplit(domain).hostname
	if not host:
		raise ValueError('Provider domain must contain a hostname')
	for name, value in cookies.items():
		client.cookies.set(name, value, domain=host, path='/')


async def get_waf_cookies_with_browser(
	account_name: str,
	login_url: str,
	required_cookies: list[str],
	*,
	use_proxy: bool = False,
):
	"""使用浏览器获取 WAF cookies"""
	print(f'[PROCESSING] {account_name}: Starting browser to get WAF cookies...')

	launch_kwargs: dict = {'headless': True}
	proxy = get_playwright_proxy(use_proxy=use_proxy)
	if proxy:
		launch_kwargs['proxy'] = proxy
	browser = await launch_async(**launch_kwargs)

	try:
		page = await browser.new_page()
		await prepare_browser_page(page)
		print(f'[PROCESSING] {account_name}: Access login page to get initial cookies...')

		await page.goto(login_url, wait_until='domcontentloaded')
		await wait_for_waf_ready(page)

		cookies = await page.context.cookies()

		waf_cookies = {}
		for cookie in cookies:
			cookie_name = cookie.get('name')
			cookie_value = cookie.get('value')
			if cookie_name in required_cookies and cookie_value is not None:
				waf_cookies[cookie_name] = cookie_value

		print(f'[INFO] {account_name}: Got {len(waf_cookies)} WAF cookies')

		missing_cookies = [c for c in required_cookies if c not in waf_cookies]

		if missing_cookies:
			print(f'[FAILED] {account_name}: Missing WAF cookies: {missing_cookies}')
			await browser.close()
			return None

		print(f'[SUCCESS] {account_name}: Successfully got all WAF cookies')
		await browser.close()
		return waf_cookies

	except Exception as e:
		print(f'[FAILED] {account_name}: Error occurred while getting WAF cookies: {e}')
		await browser.close()
		return None


async def login_with_credentials(
	account_name: str,
	provider_config,
	provider_name: str,
	email: str,
	password: str,
	*,
	initial_cookies: dict | None = None,
	api_user: str | None = None,
) -> BrowserLoginResult | None:
	"""使用用户名或邮箱与密码登录，并记录真正的登录发奖结果。"""
	print(f'[PROCESSING] {account_name}: Logging in with username/email and password...')

	login_url = f'{provider_config.domain}{provider_config.login_path}'
	settings = load_browser_login_settings(
		account_name,
		provider_name,
		persist_profile=provider_config.persist_profile,
	)
	timeout_ms = settings.wait_timeout_ms

	debug_print(
		f'[INFO] {account_name}: Browser profile={settings.profile_dir}, '
		f'persist={settings.persist_profile}, headless={settings.headless}, '
		f'humanize={settings.humanize}, timeout={timeout_ms}ms'
	)

	print(
		f'[INFO] {account_name}: Provider proxy={"enabled" if provider_config.use_proxy else "disabled"} '
		f'({provider_name})'
	)

	try:
		context = await launch_login_context(settings, use_proxy=provider_config.use_proxy)
	except Exception as e:
		print(f'[FAILED] {account_name}: Browser launch failed: {e}')
		return None

	page = None
	try:
		if initial_cookies:
			await context.add_cookies([
				{'name': name, 'value': value, 'url': provider_config.domain}
				for name, value in initial_cookies.items()
			])
		page = await context.new_page()
		await prepare_browser_page(page)
		user_info_before = None
		if provider_name == 'agentrouter':
			# 先预热站点，不等待可能因旧会话而被跳过的登录表单。
			await page.goto(provider_config.domain, wait_until='domcontentloaded', timeout=timeout_ms)
			await wait_for_waf_ready(page, timeout_ms)
			# 在登录发奖前读取旧会话余额；旧会话失效时保持未知，不伪造签到前余额。
			if initial_cookies or settings.persist_profile:
				try:
					response = await context.request.get(
						f'{provider_config.domain}{provider_config.user_info_path}',
						headers={provider_config.api_user_key: str(api_user)} if api_user else {},
						timeout=timeout_ms,
					)
					if response.status == 200:
						payload = await response.json()
						if isinstance(payload, dict) and payload.get('success') is True:
							user_info_before = user_info_from_profile(payload.get('data'))
					if not user_info_before or not user_info_before.get('success'):
						print(f'[WARN] {account_name}: 签到前余额不可用，旧会话未通过校验')
				except Exception as exc:
					# 签到前快照是可选数据，读取失败应可见，不能阻止真正的密码登录。
					print(f'[WARN] {account_name}: 签到前余额读取失败：{exc}')
			# 持久化配置也必须重新鉴权，避免复用已登录状态跳过当天奖励。
			await context.clear_cookies(name='session')
			await page.evaluate('() => localStorage.removeItem("user")')
		await navigate_login_page(
			page,
			login_url,
			timeout_ms,
			provider=provider_name,
			account_name=account_name,
		)

		login_profile = None
		if provider_name == 'agentrouter' or not await is_logged_in(page):
			if await has_session_cookie(page):
				print(f'[WARN] {account_name}: Stale session cookie on login page, forcing email login')
			await save_login_screenshot(page, provider_name, account_name, 'before-email-login')
			login_profile = await login_with_email_form(
				page,
				email,
				password,
				timeout_ms,
				provider=provider_name,
				account_name=account_name,
			)
		else:
			print(f'[INFO] {account_name}: Browser profile already logged in')

		console_url = f'{provider_config.domain}/console'
		user_profile = await verify_browser_login(
			page,
			console_url,
			timeout_ms,
			api_user=str(login_profile['id']) if login_profile else None,
			api_user_key=provider_config.api_user_key,
			user_info_path=provider_config.user_info_path,
		)
		if not user_profile:
			cookies = await context.cookies()
			cookie_names = [c.get('name') for c in cookies if c.get('name')]
			print(f'[FAILED] {account_name}: Login failed - /api/user/self not verified')
			debug_print(f'[INFO] {account_name}: Current URL: {page.url}')
			debug_print(f'[INFO] {account_name}: Got cookies: {cookie_names}')
			await save_login_screenshot(page, provider_name, account_name, 'not-authenticated')
			await context.close()
			return None

		cookies = await context.cookies(provider_config.domain)
		all_cookies = {
			cookie.get('name'): cookie.get('value') for cookie in cookies if cookie.get('name') and cookie.get('value')
		}
		api_user = str(user_profile['id']) if user_profile.get('id') is not None else None

		success_msg = f'[SUCCESS] {account_name}: Login successful, got {len(all_cookies)} cookies'
		if is_debug_enabled() and api_user:
			success_msg += f', api_user={api_user}'
		print(success_msg)
		await context.close()
		return BrowserLoginResult(
			cookies=all_cookies,
			api_user=api_user,
			user_info_before=user_info_before,
			checked_in=login_profile.get('checked_in') if login_profile else None,
		)

	except Exception as e:
		print(f'[FAILED] {account_name}: Error during login: {e}')
		if page is not None:
			await save_login_screenshot(page, provider_name, account_name, 'login-error')
		await context.close()
		return None


def user_info_from_profile(user_data: object) -> dict:
	"""只转换真实余额字段，缺失数据不能被解释为零余额。"""
	if not isinstance(user_data, dict) or 'quota' not in user_data or 'used_quota' not in user_data:
		return {'success': False, 'error': 'User profile has no balance data'}
	quota = round(user_data['quota'] / 500000, 2)
	used_quota = round(user_data['used_quota'] / 500000, 2)
	return {
		'success': True,
		'quota': quota,
		'used_quota': used_quota,
		'display': f'余额: ${quota:.2f}, 累计消耗: ${used_quota:.2f}',
	}


def get_user_info(client, headers, user_info_url: str):
	"""获取用户信息"""
	try:
		response = client.get(user_info_url, headers=headers, timeout=30)

		if response.status_code == 200:
			data = response.json()
			if isinstance(data, dict) and data.get('success') is True:
				return user_info_from_profile(data.get('data'))
			message = data.get('message', 'Invalid user info response') if isinstance(data, dict) else 'Invalid user info response'
			return {'success': False, 'error': f'Failed to get user info: {message}'}
		return {'success': False, 'error': f'Failed to get user info: HTTP {response.status_code}'}
	except Exception as e:
		return {'success': False, 'error': f'Failed to get user info: {str(e)[:50]}...'}


async def prepare_cookies(account_name: str, provider_config, user_cookies: dict) -> dict | None:
	"""准备请求所需的 cookies（可能包含 WAF cookies）"""
	waf_cookies = {}

	if provider_config.needs_waf_cookies():
		login_url = f'{provider_config.domain}{provider_config.login_path}'
		waf_cookies = await get_waf_cookies_with_browser(
			account_name,
			login_url,
			provider_config.waf_cookie_names,
			use_proxy=provider_config.use_proxy,
		)
		if not waf_cookies:
			print(f'[FAILED] {account_name}: Unable to get WAF cookies')
			return None
	else:
		print(f'[INFO] {account_name}: Bypass WAF not required, using user cookies directly')

	# 新获取的 WAF cookies 覆盖过期值，不让旧会话配置覆盖挑战结果。
	return {**user_cookies, **waf_cookies}


def execute_check_in(client, account_name: str, provider_config, headers: dict):
	"""执行签到请求"""
	print(f'[NETWORK] {account_name}: Executing check-in')

	checkin_headers = headers.copy()
	checkin_headers.update({'Content-Type': 'application/json', 'X-Requested-With': 'XMLHttpRequest'})

	sign_in_url = f'{provider_config.domain}{provider_config.sign_in_path}'
	response = client.post(sign_in_url, headers=checkin_headers, timeout=30)

	print(f'[RESPONSE] {account_name}: Response status code {response.status_code}')

	if response.status_code == 200:
		try:
			result = response.json()
			error_msg = str(result.get('msg', result.get('message', 'Unknown error')))
			already_checked_keywords = ['已经签到', '已签到', '重复签到', 'already checked', 'already signed']
			if any(keyword in error_msg.lower() for keyword in already_checked_keywords):
				print(f'[SUCCESS] {account_name}: Already checked in today')
				return '今日已签到'
			if result.get('ret') == 1 or result.get('code') == 0 or result.get('success') is True:
				print(f'[SUCCESS] {account_name}: Check-in successful!')
				return '签到成功'
			print(f'[FAILED] {account_name}: Check-in failed - {error_msg}')
			return False
		except (json.JSONDecodeError, AttributeError):
			print(f'[FAILED] {account_name}: Check-in failed - Invalid response format')
			return False
	else:
		print(f'[FAILED] {account_name}: Check-in failed - HTTP {response.status_code}')
		return False


def format_check_in_notification(detail: dict) -> str:
	"""每个账号仅占一行，未知余额明确显示为破折号。"""

	def money(value):
		return f'${value:.2f}' if value is not None else '—'

	def cell(value):
		return ' '.join(str(value).split()).replace('|', '／')

	values = [
		cell(detail['name']),
		money(detail.get('before_quota')),
		money(detail.get('before_used')),
		money(detail.get('after_quota')),
		money(detail.get('after_used')),
		cell(detail['status']),
	]
	return '| ' + ' | '.join(values) + ' |'


def format_check_in_table(details: list[dict]) -> str:
	"""终端与通知复用同一张汇总表。"""
	return '\n'.join([
		'| 账号 | 签到前余额 | 签到前消耗 | 签到后余额 | 签到后消耗 | 状态 |',
		'| --- | ---: | ---: | ---: | ---: | --- |',
		*(format_check_in_notification(detail) for detail in details),
	])


def build_check_in_detail(name: str, success: bool, before: dict | None, after: dict | None) -> dict:
	"""状态以签到响应为准，不能仅凭零余额变化判断今日已签到。"""
	detail: dict = {'name': name, 'success': success, 'status': '签到成功' if success else '失败'}
	for prefix, info in (('before', before), ('after', after)):
		if info and info.get('success'):
			detail[f'{prefix}_quota'] = info['quota']
			detail[f'{prefix}_used'] = info['used_quota']
	if after:
		detail['status'] = after.get('check_in_status', detail['status'])
	if not success:
		detail['status'] = '失败'
		error = (after or {}).get('error') or (before or {}).get('error')
		if error:
			detail['status'] = f'失败：{error}'
	return detail


async def check_in_account(account: AccountConfig, account_index: int, app_config: AppConfig):
	"""为单个账号执行签到操作"""
	account_name = account.get_display_name(account_index)
	print(f'\n[PROCESSING] Starting to process {account_name}')

	provider_config = app_config.get_provider(account.provider)
	if not provider_config:
		print(f'[FAILED] {account_name}: Provider "{account.provider}" not found in configuration')
		return False, None, None

	print(f'[INFO] {account_name}: Using provider "{account.provider}" ({provider_config.domain})')

	# 用户名或邮箱密码优先；登录失败不能回退到旧会话制造签到成功。
	all_cookies = None
	resolved_api_user: str | None = None
	auth_method = None
	login_result = None
	if account.has_login_credentials():
		print(f'[INFO] {account_name}: Attempting username/email and password login (priority)...')
		assert account.email is not None and account.password is not None
		login_result = await login_with_credentials(
			account_name,
			provider_config,
			account.provider,
			account.email,
			account.password,
			initial_cookies=get_site_cookies(account.cookies) if account.provider == 'agentrouter' else None,
			api_user=account.api_user,
		)
		if login_result:
			all_cookies = login_result.cookies
			resolved_api_user = login_result.api_user
			auth_method = 'username/email+password'
		else:
			print(f'[FAILED] {account_name}: Password login failed, will not use stale session cookies')
			return False, None, None
	elif account.has_oauth_session():
		all_cookies = await prepare_cookies(account_name, provider_config, get_site_cookies(account.cookies))
		if not all_cookies:
			return False, None, None
		return await run_agentrouter_oauth_checkin(all_cookies, account, account_name, provider_config)
	else:
		user_cookies = get_site_cookies(account.cookies) if account.provider == 'agentrouter' else parse_cookies(account.cookies)
		if not user_cookies:
			print(f'[FAILED] {account_name}: Invalid configuration format')
			return False, None, None
		all_cookies = await prepare_cookies(account_name, provider_config, user_cookies)
		auth_method = 'session cookies'

	if not all_cookies:
		return False, None, None

	print(f'[AUTH] {account_name}: Using auth method -> {auth_method}')

	return await asyncio.to_thread(
		run_check_in_requests,
		all_cookies,
		account,
		account_name,
		provider_config,
		api_user_override=resolved_api_user,
		use_proxy=provider_config.use_proxy,
		login_result=login_result,
	)


async def run_agentrouter_oauth_checkin(all_cookies, account, account_name, provider_config):
	"""OAuth 回调完成真实登录，前后余额使用同一站点会话读取。"""
	before = None
	try:
		client_kwargs: dict = {'http2': True, 'timeout': 30.0}
		proxy_url = get_proxy_server(use_proxy=provider_config.use_proxy)
		if proxy_url:
			client_kwargs['proxy'] = proxy_url
		with httpx.Client(**client_kwargs) as client:
			set_site_cookies(client, all_cookies, provider_config.domain)
			headers = get_browser_headers(provider_config.domain)
			if account.api_user:
				headers[provider_config.api_user_key] = str(account.api_user)
			user_info_url = f'{provider_config.domain}{provider_config.user_info_path}'
			before = await asyncio.to_thread(get_user_info, client, headers, user_info_url)
			oauth = AgentRouterOAuthClient(provider_config.domain)
			state = await asyncio.to_thread(oauth.fetch_oauth_state, client)
			provider = 'github' if account.github_session else 'linuxdo'
			token = account.github_session or account.linuxdo_session
			assert token is not None
			code = await oauth.authorize(provider, token, state, account_name, use_proxy=provider_config.use_proxy)
			profile = await asyncio.to_thread(oauth.callback_login, client, provider, code, state)
			headers[provider_config.api_user_key] = str(profile['id'])
			after = await asyncio.to_thread(get_user_info, client, headers, user_info_url)
			return build_login_check_in_result(profile.get('checked_in'), before, after)
	except Exception as exc:
		print(f'[FAILED] {account_name}: OAuth re-login failed - {exc}')
		return False, before, {'success': False, 'error': 'OAuth 重登录失败，请查看登录日志'}


def build_login_check_in_result(
	checked_in: bool | None, before: dict | None, after: dict
) -> tuple[bool, dict | None, dict]:
	"""余额查询成功不代表签到成功，缺少发奖标志时必须报告无法确认。"""
	if checked_in is True:
		after['check_in_status'] = '签到成功'
	elif checked_in is False:
		after['check_in_status'] = '今日已签到'
	else:
		after.setdefault('error', '登录响应缺少 checked_in，无法确认签到状态')
		return False, before, after
	return bool(after.get('success')), before, after


def run_check_in_requests(
	all_cookies: dict,
	account: AccountConfig,
	account_name: str,
	provider_config,
	*,
	api_user_override: str | None = None,
	use_proxy: bool = False,
	login_result: BrowserLoginResult | None = None,
) -> tuple[bool, dict | None, dict | None]:
	"""执行 HTTP 签到请求（同步，避免在 async 上下文中使用阻塞 httpx）。"""
	user_info_before = login_result.user_info_before if login_result else None
	try:
		client_kwargs: dict = {'http2': True, 'timeout': 30.0}
		proxy_url = get_proxy_server(use_proxy=use_proxy)
		if proxy_url:
			client_kwargs['proxy'] = proxy_url
			if is_debug_enabled():
				print(f'[INFO] {account_name}: HTTP client proxy enabled: {proxy_url}')
			else:
				print(f'[INFO] {account_name}: HTTP client proxy enabled')
		elif use_proxy:
			print(f'[WARN] {account_name}: Provider requires proxy but CHECKIN_PROXY_URL is not set')

		with httpx.Client(**client_kwargs) as client:
			set_site_cookies(client, all_cookies, provider_config.domain)

			headers = get_browser_headers(provider_config.domain)

			api_user = api_user_override or account.api_user
			if api_user:
				headers[provider_config.api_user_key] = str(api_user)

			user_info_url = f'{provider_config.domain}{provider_config.user_info_path}'
			if provider_config.name == 'agentrouter' and not provider_config.needs_manual_check_in():
				user_info_after = get_user_info(client, headers, user_info_url)
				if login_result:
					return build_login_check_in_result(login_result.checked_in, user_info_before, user_info_after)
				user_info_after.setdefault('error', 'AgentRouter 需要配置 email+password 或 OAuth 会话重新登录')
				return False, user_info_after.copy(), user_info_after

			user_info_before = get_user_info(client, headers, user_info_url)
			if not user_info_before.get('success'):
				print(user_info_before.get('error', 'Unknown error'))

			if provider_config.needs_manual_check_in():
				status = execute_check_in(client, account_name, provider_config, headers)
				user_info_after = get_user_info(client, headers, user_info_url)
				user_info_after['check_in_status'] = status or '签到失败'
				return bool(status) and bool(user_info_after.get('success')), user_info_before, user_info_after

			user_info_after = get_user_info(client, headers, user_info_url)
			if user_info_after and user_info_after.get('success'):
				print(f'[INFO] {account_name}: Check-in completed automatically (triggered by user info request)')
				return True, user_info_before, user_info_after
			error = user_info_after.get('error', 'Unknown error') if user_info_after else 'Unknown error'
			print(f'[FAILED] {account_name}: Auto check-in failed - {error}')
			return False, user_info_before, user_info_after

	except Exception as e:
		print(f'[FAILED] {account_name}: Error occurred during check-in process - {str(e)[:50]}...')
		return False, user_info_before, {'success': False, 'error': f'签到请求失败：{str(e)[:50]}'}


async def main():
	"""主函数"""
	if is_debug_enabled():
		print('[INFO] DEBUG_MODE enabled')
		proxy_server = os.getenv('CHECKIN_PROXY_URL', '').strip()
		if proxy_server:
			print(f'[INFO] Proxy endpoint available: {proxy_server} (enabled per provider use_proxy)')
		else:
			print('[INFO] CHECKIN_PROXY_URL not set; providers with use_proxy=true will run without proxy')
	else:
		print('[INFO] Debug mode disabled (set DEBUG_MODE=true to enable screenshots and verbose logs)')

	print('[SYSTEM] AnyRouter.top multi-account auto check-in script started')
	print(f'[TIME] Execution time: {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}')

	app_config = AppConfig.load_from_env()
	print(f'[INFO] Loaded {len(app_config.providers)} provider configuration(s)')
	if is_debug_enabled():
		for provider_name, provider in sorted(app_config.providers.items()):
			print(f'[INFO] Provider "{provider_name}": use_proxy={provider.use_proxy}')

	accounts = load_accounts_config()
	if not accounts:
		error_msg = '[FAILED] Unable to load account configuration, program exits'
		print(error_msg)
		notify.push_message('AnyRouter Check-in Alert', error_msg, msg_type='text')
		sys.exit(1)

	print(f'[INFO] Found {len(accounts)} account configurations')

	last_balance_hash = load_balance_hash()

	success_count = 0
	total_count = len(accounts)
	current_balances = {}
	account_check_in_details = []
	need_notify = False

	for i, account in enumerate(accounts):
		account_key = f'account_{i + 1}'
		try:
			success, user_info_before, user_info_after = await check_in_account(account, i, app_config)
			if success:
				success_count += 1

			if not success:
				need_notify = True
				account_name = account.get_display_name(i)
				print(f'[NOTIFY] {account_name} failed, will send notification')

			if user_info_after and user_info_after.get('success'):
				current_quota = user_info_after['quota']
				current_used = user_info_after['used_quota']
				current_balances[account_key] = {'quota': current_quota, 'used': current_used}

			account_check_in_details.append(
				build_check_in_detail(account.get_display_name(i), success, user_info_before, user_info_after)
			)

		except Exception as e:
			account_name = account.get_display_name(i)
			print(f'[FAILED] {account_name} processing exception: {e}')
			need_notify = True
			account_check_in_details.append(
				build_check_in_detail(account_name, False, None, {'error': f'处理异常：{str(e)[:50]}'})
			)

	current_balance_hash = generate_balance_hash(current_balances) if current_balances else None
	if current_balance_hash:
		if last_balance_hash is None:
			need_notify = True
			print('[NOTIFY] First run detected, will send notification with current balances')
		elif current_balance_hash != last_balance_hash:
			need_notify = True
			print('[NOTIFY] Balance changes detected, will send notification')
		else:
			print('[INFO] No balance changes detected')

	if current_balance_hash:
		save_balance_hash(current_balance_hash)

	notification_table = format_check_in_table(account_check_in_details)
	print('\n' + notification_table)
	if need_notify and account_check_in_details:
		summary = [
			'[STATS] Check-in result statistics:',
			f'[SUCCESS] Success: {success_count}/{total_count}',
			f'[FAIL] Failed: {total_count - success_count}/{total_count}',
		]

		if success_count == total_count:
			summary.append('[SUCCESS] All accounts check-in successful!')
		elif success_count > 0:
			summary.append('[WARN] Some accounts check-in successful')
		else:
			summary.append('[ERROR] All accounts check-in failed')

		time_info = f'[TIME] Execution time: {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}'

		notify_content = '\n\n'.join([time_info, notification_table, '\n'.join(summary)])
		screenshot_paths = take_pending_screenshots() if is_debug_enabled() else []
		if screenshot_paths:
			github_run_id = os.getenv('GITHUB_RUN_ID', '').strip()
			github_repo = os.getenv('GITHUB_REPOSITORY', '').strip()
			screenshot_hint = f'[SCREENSHOT] {len(screenshot_paths)} debug screenshot(s) saved'
			if github_run_id and github_repo:
				run_url = f'https://github.com/{github_repo}/actions/runs/{github_run_id}'
				screenshot_hint += f'. Download artifact `checkin-screenshots-{github_run_id}` from: {run_url}'
			else:
				screenshot_hint += ' to `checkin_screenshots/`'
			notify_content += f'\n\n{screenshot_hint}'

		print('\n'.join(summary))
		notify.push_message('AnyRouter Check-in Alert', notify_content, msg_type='text')
		print('[NOTIFY] Notification sent due to failures or balance changes')
	else:
		print('[INFO] All accounts successful and no balance changes detected, notification skipped')

	sys.exit(0 if success_count > 0 else 1)


def run_main():
	"""运行主函数的包装函数"""
	try:
		asyncio.run(main())
	except KeyboardInterrupt:
		print('\n[WARNING] Program interrupted by user')
		sys.exit(1)
	except Exception as e:
		print(f'\n[FAILED] Error occurred during program execution: {e}')
		sys.exit(1)


if __name__ == '__main__':
	run_main()
