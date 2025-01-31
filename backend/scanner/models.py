from django.db import models

class Scan(models.Model):
    url = models.URLField(max_length=200)
    status_code = models.IntegerField()
    vulnerabilities_found = models.BooleanField(default=False)
    scan_date = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"Scan for {self.url} on {self.scan_date}"

class Vulnerability(models.Model):
    scan = models.ForeignKey(Scan, related_name='vulnerabilities', on_delete=models.CASCADE)
    vulnerability_type = models.CharField(max_length=255)
    description = models.TextField()
    level = models.CharField(max_length=50, choices=[('High', 'High'), ('Medium', 'Medium'), ('Low', 'Low')], default='High')
    url = models.URLField(max_length=200)

    def __str__(self):
        return f"{self.vulnerability_type} for {self.url}"
