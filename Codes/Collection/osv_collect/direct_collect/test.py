import asyncio
from crawl4ai import *

async def main():
    async with AsyncWebCrawler() as crawler:
        result = await crawler.arun(
            url="https://www.example.com",
        )
        print(result.markdown)
        # print(result)

if __name__ == "__main__":
    asyncio.run(main())
