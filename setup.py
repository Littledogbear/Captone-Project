
from setuptools import setup, find_packages

setup(
    name="cyber_attack_tracer",
    version="0.1.0",
    packages=find_packages(),
    install_requires=[
        line.strip() for line in open("requirements.txt")
        if not line.strip().startswith("#")
    ],
    author="Devin AI",
    author_email="devin-ai-integration[bot]@users.noreply.github.com",
    description="Cyber Attack Trace Collector and Analyzer System",
    keywords="cybersecurity, malware, analysis, ember",
    python_requires=">=3.8",
)
