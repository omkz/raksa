import httpx

from app.config import settings


class TavilyService:
    @property
    def configured(self) -> bool:
        return bool(settings.tavily_api_key)

    async def research_sql_injection(self) -> list[dict[str, str]]:
        if not self.configured:
            return []
        payload = {
            "api_key": settings.tavily_api_key,
            "query": "OWASP SQL Injection Prevention Cheat Sheet parameterized queries CWE-89",
            "search_depth": "basic",
            "max_results": 4,
            "include_domains": ["owasp.org", "cwe.mitre.org", "cheatsheetseries.owasp.org"],
            "include_answer": False,
        }
        async with httpx.AsyncClient(timeout=15) as client:
            response = await client.post("https://api.tavily.com/search", json=payload)
            response.raise_for_status()
            data = response.json()
        return [
            {
                "title": str(item.get("title", "Security guidance"))[:300],
                "url": str(item.get("url", ""))[:1000],
                "content": str(item.get("content", ""))[:1500],
            }
            for item in data.get("results", [])[:4]
        ]


tavily = TavilyService()
