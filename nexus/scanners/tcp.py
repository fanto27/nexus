import asyncio, socket, contextlib
from nexus.core.models import Service

async def scan_tcp(targets: list[str], ports: list[int], timeout: float = 0.6, concurrency: int = 128, progress = None) -> list[Service]:
    queue = asyncio.Queue()
    found = []
    completed = 0
    total = len(targets) * len(ports)

    async def probe(address: str, port: int) -> Service | None:
        try:
            _, writer = await asyncio.wait_for(asyncio.open_connection(address, port), timeout=timeout)
            writer.close()
            with contextlib.suppress(Exception): await writer.wait_closed()
            try: name = socket.getservbyport(port, "tcp")
            except: name = "unknown"
            return Service(address=address, port=port, protocol="tcp", state="open", name=name)
        except: return None

    async def worker():
        nonlocal completed
        while True:
            item = await queue.get()
            if item is None: break
            svc = await probe(item[0], item[1])
            if svc: found.append(svc)
            completed += 1
            if progress: progress(completed, total)
            queue.task_done()

    workers = [asyncio.create_task(worker()) for _ in range(concurrency)]
    for address in targets:
        for port in ports: await queue.put((address, port))
    for _ in workers: await queue.put(None)
    await asyncio.gather(*workers)
    return found
