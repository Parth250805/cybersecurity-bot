from setuptools import setup, find_packages

setup(
    name="cybersecurity-bot",
    version="0.1.0",
    packages=find_packages(),
    install_requires=[
        "python-dotenv>=0.19.0",
        "requests>=2.26.0",
        "PyYAML>=5.4.1",
        "colorama>=0.4.4",
        "psutil>=5.8.0",
        "plyer>=2.0.0",
        "scikit-learn>=0.24.2",
        "pandas>=1.3.0",
        "numpy>=1.21.0",
    ],
    python_requires=">=3.7",
    entry_points={
        "console_scripts": [
            "cybersecurity-bot=cybersecurity_bot.gui.simple_gui:main",
        ],
    },
    author="Parth250805",
    description="A Python-based cybersecurity monitoring tool with real-time process detection",
    long_description=open("README.md", encoding="utf-8").read(),
    long_description_content_type="text/markdown",
    url="https://github.com/Parth250805/cybersecurity-bot",
    classifiers=[
        "Development Status :: 3 - Alpha",
        "Intended Audience :: System Administrators",
        "License :: OSI Approved :: MIT License",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.7",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
    ],
)