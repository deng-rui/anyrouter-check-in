"""参考 suainam/anyrouter-autolog 的浏览器请求头，统一 HTTP 请求指纹。"""

from __future__ import annotations

from typing import Mapping

DEFAULT_USER_AGENT = (
	'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 '
	'(KHTML, like Gecko) Chrome/130.0.0.0 Safari/537.36'
)


def get_browser_headers(domain: str, extra: Mapping[str, str] | None = None) -> dict[str, str]:
	"""Chrome 版本与 Client Hints 保持一致；压缩方式交由 httpx 按解码能力声明。"""
	clean_domain = domain.rstrip('/')
	headers = {
		'User-Agent': DEFAULT_USER_AGENT,
		'Accept': 'application/json, text/plain, */*',
		'Accept-Language': 'zh-CN,zh;q=0.9,en;q=0.8',
		'sec-ch-ua': '"Chromium";v="130", "Google Chrome";v="130", "Not?A_Brand";v="99"',
		'sec-ch-ua-mobile': '?0',
		'sec-ch-ua-platform': '"Windows"',
		'Sec-Fetch-Dest': 'empty',
		'Sec-Fetch-Mode': 'cors',
		'Sec-Fetch-Site': 'same-origin',
		'Origin': clean_domain,
		'Referer': f'{clean_domain}/',
	}
	if extra:
		headers.update(extra)
	return headers
