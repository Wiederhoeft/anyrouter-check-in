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

import httpx
from dotenv import load_dotenv
from playwright.async_api import async_playwright

load_dotenv()

from utils.config import AccountConfig, AppConfig, load_accounts_config
from utils.notify import notify

BALANCE_HASH_FILE = 'balance_hash.txt'


def load_balance_hash():
	"""加载余额hash"""
	try:
		if os.path.exists(BALANCE_HASH_FILE):
			with open(BALANCE_HASH_FILE, 'r', encoding='utf-8') as f:
				return f.read().strip()
	except Exception:
		pass
	return None


def save_balance_hash(balance_hash):
	"""保存余额hash"""
	try:
		with open(BALANCE_HASH_FILE, 'w', encoding='utf-8') as f:
			f.write(balance_hash)
	except Exception as e:
		print(f'[WARNING] 保存余额哈希失败：{e}')


def generate_balance_hash(balances):
	"""生成余额数据的hash"""
	# 将包含 quota 和 used 的结构转换为简单的 quota 值用于 hash 计算
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


async def get_waf_cookies_with_playwright(account_name: str, login_url: str):
	"""使用 Playwright 获取 WAF cookies（隐私模式）"""
	print(f'[PROCESSING] {account_name}: 正在启动浏览器获取 WAF cookies...')

	async with async_playwright() as p:
		import tempfile

		with tempfile.TemporaryDirectory() as temp_dir:
			context = await p.chromium.launch_persistent_context(
				user_data_dir=temp_dir,
				headless=False,
				user_agent='Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36',
				viewport={'width': 1920, 'height': 1080},
				args=[
					'--disable-blink-features=AutomationControlled',
					'--disable-dev-shm-usage',
					'--disable-web-security',
					'--disable-features=VizDisplayCompositor',
					'--no-sandbox',
				],
			)

			page = await context.new_page()

			try:
				print(f'[PROCESSING] {account_name}: 访问登录页面以获取初始 cookies...')

				await page.goto(login_url, wait_until='networkidle')

				try:
					await page.wait_for_function('document.readyState === "complete"', timeout=5000)
				except Exception:
					await page.wait_for_timeout(3000)

				cookies = await page.context.cookies()

				waf_cookies = {}
				for cookie in cookies:
					cookie_name = cookie.get('name')
					cookie_value = cookie.get('value')
					if cookie_name in ['acw_tc', 'cdn_sec_tc', 'acw_sc__v2'] and cookie_value is not None:
						waf_cookies[cookie_name] = cookie_value

				print(f'[INFO] {account_name}: 获取到 {len(waf_cookies)} 条 WAF cookies')

				required_cookies = ['acw_tc', 'cdn_sec_tc', 'acw_sc__v2']
				missing_cookies = [c for c in required_cookies if c not in waf_cookies]

				if missing_cookies:
					print(f'[FAILED] {account_name}: 缺少 WAF cookies：{missing_cookies}')
					await context.close()
					return None

				print(f'[SUCCESS] {account_name}: 已成功获取全部 WAF cookies')

				await context.close()

				return waf_cookies

			except Exception as e:
				print(f'[FAILED] {account_name}: 获取 WAF cookies 时出现错误：{e}')
				await context.close()
				return None


async def get_user_info(client, headers, user_info_url: str):
	"""获取用户信息"""
	try:
		response = await client.get(user_info_url, headers=headers, timeout=30)

		if response.status_code == 200:
			data = response.json()
			if data.get('success'):
				user_data = data.get('data', {})
				quota = round(user_data.get('quota', 0) / 500000, 2)
				used_quota = round(user_data.get('used_quota', 0) / 500000, 2)
				return {
					'success': True,
					'quota': quota,
					'used_quota': used_quota,
					'display': f':money: 当前余额：${quota}，已用：${used_quota}',
				}
		return {'success': False, 'error': f'获取用户信息失败：HTTP {response.status_code}'}
	except Exception as e:
		return {'success': False, 'error': f'获取用户信息失败：{str(e)[:50]}...'}


async def prepare_cookies(account_name: str, provider_config, user_cookies: dict) -> dict | None:
	"""准备请求所需的 cookies（可能包含 WAF cookies）"""
	waf_cookies = {}

	if provider_config.needs_waf_cookies():
		login_url = f'{provider_config.domain}{provider_config.login_path}'
		waf_cookies = await get_waf_cookies_with_playwright(account_name, login_url)
		if not waf_cookies:
			print(f'[FAILED] {account_name}: 无法获取 WAF cookies')
			return None
	else:
		print(f'[INFO] {account_name}: 无需绕过 WAF，直接使用用户 cookies')

	return {**waf_cookies, **user_cookies}


async def execute_check_in(client, account_name: str, provider_config, headers: dict):
	"""执行签到请求"""
	print(f'[NETWORK] {account_name}: 开始执行签到请求')

	checkin_headers = headers.copy()
	checkin_headers.update({'Content-Type': 'application/json', 'X-Requested-With': 'XMLHttpRequest'})

	sign_in_url = f'{provider_config.domain}{provider_config.sign_in_path}'
	response = await client.post(sign_in_url, headers=checkin_headers, timeout=30)

	print(f'[RESPONSE] {account_name}: 响应状态码 {response.status_code}')

	if response.status_code == 200:
		try:
			result = response.json()
			if result.get('ret') == 1 or result.get('code') == 0 or result.get('success'):
				print(f'[SUCCESS] {account_name}: 签到成功！')
				return True
			else:
				error_msg = result.get('msg', result.get('message', '未知错误'))
				print(f'[FAILED] {account_name}: 签到失败 - {error_msg}')
				return False
		except json.JSONDecodeError:
			# 如果不是 JSON 响应，检查是否包含成功标识
			if 'success' in response.text.lower():
				print(f'[SUCCESS] {account_name}: 签到成功！')
				return True
			else:
				print(f'[FAILED] {account_name}: 签到失败 - 响应格式无效')
				return False
	else:
		print(f'[FAILED] {account_name}: 签到失败 - HTTP {response.status_code}')
		return False


async def check_in_account(account: AccountConfig, account_index: int, app_config: AppConfig):
	"""为单个账号执行签到操作"""
	account_name = account.get_display_name(account_index)
	print(f'\n[PROCESSING] 开始处理 {account_name}')

	provider_config = app_config.get_provider(account.provider)
	if not provider_config:
		print(f'[FAILED] {account_name}: 配置中未找到服务商 "{account.provider}"')
		return False, None

	print(f'[INFO] {account_name}: 使用服务商 \"{account.provider}\"（{provider_config.domain}）')

	user_cookies = parse_cookies(account.cookies)
	if not user_cookies:
		print(f'[FAILED] {account_name}: 配置格式无效')
		return False, None

	all_cookies = await prepare_cookies(account_name, provider_config, user_cookies)
	if not all_cookies:
		return False, None

	try:
		async with httpx.AsyncClient(http2=True, timeout=30.0) as client:
			client.cookies.update(all_cookies)

			headers = {
				'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36',
				'Accept': 'application/json, text/plain, */*',
				'Accept-Language': 'zh-CN,zh;q=0.9,en;q=0.8',
				'Accept-Encoding': 'gzip, deflate, br, zstd',
				'Referer': provider_config.domain,
				'Origin': provider_config.domain,
				'Connection': 'keep-alive',
				'Sec-Fetch-Dest': 'empty',
				'Sec-Fetch-Mode': 'cors',
				'Sec-Fetch-Site': 'same-origin',
				provider_config.api_user_key: account.api_user,
			}

			user_info_url = f'{provider_config.domain}{provider_config.user_info_path}'
		user_info = await get_user_info(client, headers, user_info_url)
		if user_info and user_info.get('success'):
			print(user_info['display'])
		elif user_info:
			print(user_info.get('error', '未知错误'))

			if provider_config.needs_manual_check_in():
				success = await execute_check_in(client, account_name, provider_config, headers)
				return success, user_info
			else:
				print(f'[INFO] {account_name}: 请求用户信息已触发自动签到，流程结束')
				return True, user_info
	except Exception as e:
		print(f'[FAILED] {account_name}: 签到流程出现异常 - {str(e)[:50]}...')
		return False, None


async def main():
	"""主函数"""
	print('[SYSTEM] AnyRouter.top 多账号自动签到脚本启动（使用 Playwright）')
	print(f'[TIME] 执行时间：{datetime.now().strftime("%Y-%m-%d %H:%M:%S")}')

	app_config = AppConfig.load_from_env()
	print(f'[INFO] 已加载 {len(app_config.providers)} 组服务商配置')

	accounts = load_accounts_config()
	if not accounts:
		print('[FAILED] 无法加载账号配置，程序即将退出')
		sys.exit(1)

	print(f'[INFO] 检测到 {len(accounts)} 个账号配置')

	last_balance_hash = load_balance_hash()

	success_count = 0
	total_count = len(accounts)
	current_balances = {}
	notified_accounts = set()
	failure_items = []
	balance_items = []
	need_notify = False  # 是否需要发送通知
	balance_changed = False  # 余额是否有变化

	for i, account in enumerate(accounts):
		account_key = f'account_{i + 1}'
		provider_config = app_config.get_provider(account.provider)
		provider_domain = provider_config.domain if provider_config else account.provider

		try:
			success, user_info = await check_in_account(account, i, app_config)
			if success:
				success_count += 1

			account_name = account.get_display_name(i)
			should_notify_this_account = not success

			if should_notify_this_account:
				need_notify = True
				print(f'[NOTIFY] {account_name} 签到失败，将发送通知')

			if user_info and user_info.get('success'):
				current_quota = user_info['quota']
				current_used = user_info['used_quota']
				current_balances[account_key] = {
					'quota': current_quota,
					'used': current_used,
					'provider': provider_domain,
				}
			elif user_info:
				error_detail = user_info.get('error', '未知错误')
				if account_key not in notified_accounts:
					failure_items.append(
						{'account': account_name, 'detail': error_detail, 'provider': provider_domain}
					)
					notified_accounts.add(account_key)
				need_notify = True

			if should_notify_this_account and account_key not in notified_accounts:
				error_detail = '未提供更多信息'
				if user_info and user_info.get('error'):
					error_detail = user_info.get('error', '未知错误')
				failure_items.append(
					{'account': account_name, 'detail': error_detail, 'provider': provider_domain}
				)
				notified_accounts.add(account_key)

		except Exception as e:
			account_name = account.get_display_name(i)
			print(f'[FAILED] {account_name} 处理过程出现异常：{e}')
			need_notify = True  # 异常也需要通知
			failure_items.append(
				{'account': account_name, 'detail': f'异常：{str(e)[:80]}...', 'provider': provider_domain}
			)
			notified_accounts.add(account_key)

	# 检查余额变化
	current_balance_hash = generate_balance_hash(current_balances) if current_balances else None
	if current_balance_hash:
		if last_balance_hash is None:
			# 首次运行
			balance_changed = True
			need_notify = True
			print('[NOTIFY] 检测到首次运行，将发送当前余额通知')
		elif current_balance_hash != last_balance_hash:
			# 余额有变化
			balance_changed = True
			need_notify = True
			print('[NOTIFY] 检测到账户余额变化，将发送通知')
		else:
			print('[INFO] 未检测到余额变化')

	# 为有余额变化的情况添加所有成功账号到通知内容
	if balance_changed:
		for i, account in enumerate(accounts):
			account_key = f'account_{i + 1}'
			if account_key in current_balances:
				account_name = account.get_display_name(i)
				# 只添加成功获取余额的账号，且避免重复添加
				if account_key not in notified_accounts:
					balance_items.append(
						{
							'provider': current_balances[account_key]['provider'],
							'account': account_name,
							'quota': current_balances[account_key]['quota'],
							'used': current_balances[account_key]['used'],
						}
					)
					notified_accounts.add(account_key)

	# 保存当前余额hash
	if current_balance_hash:
		save_balance_hash(current_balance_hash)

	if need_notify:
		# 构建 Markdown 通知内容
		status_line = '[成功] 所有账号签到成功！'

		if success_count == total_count:
			status_line = '[成功] 所有账号签到成功！'
		elif success_count > 0:
			status_line = '[提示] 部分账号签到成功'
		else:
			status_line = '[错误] 所有账号签到失败'

		title_block = '# 📬 AnyRouter 签到提醒'
		time_info = f'> ⏱️ 执行时间：{datetime.now().strftime("%Y-%m-%d %H:%M:%S")}'
		stats_block = '\n'.join(
			[
				'## 📊 签到统计',
				f'- ✅ 成功：{success_count}/{total_count}',
				f'- ❌ 失败：{total_count - success_count}/{total_count}',
				f'- 🏁 状态：{status_line}',
			]
		)

		sections = [title_block, time_info, stats_block]

		if failure_items:
			failure_lines = [
				'## ⚠️ 签到异常',
				'| 平台 | 账号 | 情况说明 |',
				'| :--- | :--- | :------- |',
			]
			for item in failure_items:
				failure_lines.append(f'| {item.get("provider", "未识别")} | {item["account"]} | {item["detail"]} |')
			sections.append('\n'.join(failure_lines))

		if balance_items:
			balance_lines = [
				'## 💰 账户余额',
				'| 平台 | 账号 | 当前余额 ($) | 已用 ($) |',
				'| :--- | :--- | -----------: | -------: |',
			]
			for item in balance_items:
				balance_lines.append(
					f'| {item.get("provider", "未识别")} | {item["account"]} | {item["quota"]:.2f} | {item["used"]:.2f} |'
				)
			sections.append('\n'.join(balance_lines))
		else:
			sections.append('## 💰 账户余额\n> 暂无可展示余额数据，可能未成功获取账户配额信息。')

		if not failure_items:
			sections.append('## ✅ 全部账号状态\n> 未检测到异常账号。')

		sections.append('---\n> 如需查看更多日志，请检查脚本运行终端输出。')

		notify_content = '\n\n'.join(sections)

		print(notify_content)
		notify.push_message('AnyRouter 签到提醒', notify_content, msg_type='text')
		print('[NOTIFY] 因失败或余额变化已发送通知')
	else:
		print('[INFO] 所有账号签到成功且余额无变化，跳过通知')

	# 设置退出码
	sys.exit(0 if success_count > 0 else 1)


def run_main():
	"""运行主函数的包装函数"""
	try:
		asyncio.run(main())
	except KeyboardInterrupt:
		print('\n[WARNING] 程序被用户中断')
		sys.exit(1)
	except Exception as e:
		print(f'\n[FAILED] 程序执行出现错误：{e}')
		sys.exit(1)


if __name__ == '__main__':
	run_main()
