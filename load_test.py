import requests
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
import statistics


def test_endpoint(url, num_requests=100):
    """Test un endpoint avec N requêtes"""
    times = []
    errors = 0

    def make_request():
        try:
            start = time.time()
            response = requests.get(url, timeout=10)
            elapsed = time.time() - start
            return elapsed, response.status_code
        except Exception as e:
            return None, str(e)

    # Requêtes parallèles
    with ThreadPoolExecutor(max_workers=10) as executor:
        futures = [executor.submit(make_request) for _ in range(num_requests)]

        for future in as_completed(futures):
            elapsed, status = future.result()
            if elapsed:
                times.append(elapsed)
            else:
                errors += 1

    if times:
        print(f"\n📊 {url}")
        print(f"   Requests: {num_requests}")
        print(f"   Success: {len(times)}")
        print(f"   Errors: {errors}")
        print(f"   Avg: {statistics.mean(times)*1000:.1f}ms")
        print(f"   Min: {min(times)*1000:.1f}ms")
        print(f"   Max: {max(times)*1000:.1f}ms")
        print(f"   P95: {statistics.quantiles(times, n=20)[18]*1000:.1f}ms")

    return len(times), errors


# Test endpoints
print("🚀 Load Testing SecureTrack...")
print("=" * 50)

endpoints = [
    "http://localhost:8000/api/health/",
    "http://localhost:8000/api/",
]

for url in endpoints:
    test_endpoint(url, num_requests=200)

print("\n" + "=" * 50)
print("✅ Load test completed!")
