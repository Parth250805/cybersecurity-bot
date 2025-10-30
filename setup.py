from setuptools import setup, find_packages

setup(
    name="cybersecurity-bot",
    version="0.1.0",
    packages=find_packages(),
    install_requires=[
        "python-dotenv>=1.0.0",
        "requests>=2.31.0",
        "PyYAML>=6.0.1",
        "colorama>=0.4.6",
        "psutil>=5.9.5",
        "plyer>=2.1.0",
        "scikit-learn>=1.3.0",
        "pandas>=2.1.0",
        "numpy>=1.24.0",
        "Pillow>=10.0.0",
        "pytest>=7.4.0",
        "pytest-cov>=4.1.0",
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