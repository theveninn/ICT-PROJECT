import requests
from bs4 import BeautifulSoup
from urllib.parse import urlparse
from django.http import JsonResponse, HttpResponse
from .models import Scan, Vulnerability
from urllib.parse import urlparse

# Minimal home view to handle the root path
def home(request):
    return HttpResponse("Welcome to the Scanner!")

def is_valid_url(url):
    parsed_url = urlparse(url)
    # Check if the URL has both a scheme and netloc (domain part)
    return bool(parsed_url.scheme) and bool(parsed_url.netloc)

def format_url(url):
    if not urlparse(url).scheme:
        return f'http://{url}'  # Add http:// if no scheme (http/https) is provided
    return url

# Scan a website and save to the database
def scan_website(request):
    url = request.GET.get('url')
    
    if not url:
        return JsonResponse({"error": "No URL provided"}, status=400)

    formatted_url = format_url(url)

    if not is_valid_url(formatted_url):
        return JsonResponse({"error": "Invalid URL format"}, status=400)

    vulnerabilities = []

    try:
        # Send an HTTP request to the URL
        response = requests.get(formatted_url)
        soup = BeautifulSoup(response.text, 'html.parser')

        # Check for SQL Injection vulnerability
        if 'sql' in formatted_url.lower():
            vulnerabilities.append("Possible SQL Injection vulnerability found!")

        # Check for Cross-Site Scripting (XSS)
        if '<script>' in response.text.lower():
            vulnerabilities.append("Possible XSS vulnerability found!")

        # Check for missing security headers (e.g., Content-Security-Policy)
        if 'content-security-policy' not in response.headers:
            vulnerabilities.append("Missing Content-Security-Policy header.")

        # Check for insecure HTTP methods (e.g., DELETE, PUT)
        if 'DELETE' in response.headers.get('allow', '') or 'PUT' in response.headers.get('allow', ''):
            vulnerabilities.append("Insecure HTTP method allowed (DELETE or PUT).")

        # Save the scan data to the database
        scan = Scan.objects.create(
            url=formatted_url,
            status_code=response.status_code,
            vulnerabilities_found=bool(vulnerabilities),
        )

        # Save vulnerabilities to the database
        for vuln in vulnerabilities:
            Vulnerability.objects.create(
                scan=scan,
                vulnerability_type=vuln,
                description=vuln,  # You can add more detailed descriptions if needed
                level='High',  # You can update the level as needed
                url=formatted_url
            )

        return JsonResponse({
            "url": formatted_url,
            "status_code": response.status_code,
            "vulnerabilities": vulnerabilities,
            "scan_id": scan.id
        })

    except requests.exceptions.RequestException as e:
        return JsonResponse({"error": str(e)}, status=500)

# View to get past scans from the database
def past_scans(request):
    scans = Scan.objects.all().order_by('-scan_date')  # Fetch scans, newest first
    scan_data = []
    for scan in scans:
        # Collecting vulnerabilities for each scan
        vulnerabilities = [{"type": vuln.vulnerability_type, "description": vuln.description} for vuln in scan.vulnerabilities.all()]
        scan_data.append({
            "url": scan.url,
            "status_code": scan.status_code,
            "vulnerabilities_found": scan.vulnerabilities_found,
            "scan_date": scan.scan_date,
            "vulnerabilities": vulnerabilities,
        })
    
    return JsonResponse({"past_scans": scan_data})
