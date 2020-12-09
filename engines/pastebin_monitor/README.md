# DEV STATUS: STILL IN BETA

## Description
PastebinMonitor PatrOwl engine to crawl pastebin with or without API key with a proxy list.

## Dependencies
- Python 3
- `pip3 install -r requirements.txt`
- Configure PastebinMonitor `pastebin_monitor.json.sample` and rename it to `pastebin_monitor.json`
- Set your proxies list if you want to use them `proxies.txt`
- Set your user-agents list `useragents.txt`
- Run the crawler: `python3 engine-pastebin_crawler.py`
- Run the monitor: `python3 engine-pastebin_monitor.py`

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details
