import asyncio

async def async_leaf():
    await asyncio.sleep(30)

async def async_caller():
    await async_leaf()

asyncio.run(async_caller())
