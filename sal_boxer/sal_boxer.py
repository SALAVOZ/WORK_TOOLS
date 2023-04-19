import threading
import time
import aiohttp
import aiohttp.client_exceptions
import asyncio
import argparse

'''
async def by_aiohttp_concurrency(url):
    async with aiohttp.ClientSession() as session:
        tasks = []
        tasks.append(asyncio.create_task(fetch(url, session)))
        original_result = await asyncio.gather(*tasks)
        for res in original_result:
            print(res)
'''


'''
async def brute(url):
    async with aiohttp.ClientSession(trust_env=True) as session:
        async with session.get(url) as response:
            if response.status != 404:
                print('Status:', response.status, 'Url:', url)

async def run(url):
    await brute(url)

def aioloop(url):
    #loop = asyncio.get_event_loop()
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    future = loop.run_until_complete(run(url))
    loop.run_until_complete(future)
'''

'''
async def query(session, url):
    try:
        async with session.get(url) as response:
            print('Status:', response.status, 'Url:', url)
    except Exception:
        print('Exception')
'''

'''
async def brute():
    words = [word.replace('\n', '') for word in open('C:\sal_boxer\common.txt', 'r').readlines()]
    async with aiohttp.ClientSession() as session:
        tasks = []
        for word in words:
            url = f'http://10.11.6.222:8000/' + word
            tasks.append(asyncio.ensure_future(query(session, url)))
        await asyncio.gather(*tasks)
'''


async def fetch(url, session):
    try:
        async with session.get(url, ) as response:
            print('Status:', response.status, 'Url:', url)
    except Exception:
        pass


async def bound_fetch(sem, url, session):
    async with sem:
        return await fetch(url, session)


async def by_aiohttp_concurrency_with_semaphore(url, words):
    sem = asyncio.Semaphore(100)
    async with aiohttp.ClientSession() as session:
        tasks = []
        for word in words:
            tasks.append(asyncio.create_task(bound_fetch(sem, url + word, session)))
        await asyncio.gather(*tasks)


def run_thread(url, words):
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)

    loop.run_until_complete(by_aiohttp_concurrency_with_semaphore(url, words))
    loop.close()


if __name__ == '__main__':
    parser = argparse.ArgumentParser(
        description="Sal_Boxer."
    )
    parser.add_argument(
        "-u",
        '--url',
        required=True,
        help="This is a list of URL(s).",
    )
    parser.add_argument(
        "-w",
        '--wordlist',
        required=True,
        help="This is the wordslist for directory bruteforcing",
    )
    parser.add_argument(
        "-t",
        '--thread',
        required=False,
        default=1,
        help="This is count of threads",
    )
    parser.add_argument(
        '-r',
        '--recursion',
        required=False
    )
    args = parser.parse_args()

    words = [word.replace('\n', '') for word in open(args.wordlist, 'r').readlines()]
    length = len(words)
    count_of_threads = 2
    words_splited = [words[int( i / count_of_threads * length ) : int( (i + 1) / count_of_threads * length )] for i in range(count_of_threads)]
    url = args.url
    start_time = time.time()
    threads = [threading.Thread(target=run_thread, args=(url, splited)) for splited in words_splited]
    for thread in threads:
        thread.start()

    for thread in threads:
        thread.join()

    print("--- %s seconds ---" % (time.time() - start_time))

import subprocess

process = subprocess.Popen('whoami', stdout=subprocess.PIPE, stderr=subprocess.PIPE)

