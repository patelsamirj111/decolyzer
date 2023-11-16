from distutils.core import setup

long_description = """
    package name: decolyzer
    description: the package has multiple functions in it as below:
    
    decogoat: This is a decorator function which will help to run commands/processes/scripts 
    (e.g. tcpdump/top etc.) before and after the execution of your own function.
    The function will delete any existing files before the execution of your own function.
    The function will also rename the files after the execution of your own function.
    
    Ssh class: This is a class based off of paramiko package and will help create ssh connections.
    
    scp_operation: This function mimics scp command of linux/unix os.
    
    analyze_capture: This is a function to parse traffic capture such as e.g. capture.pcap
    
    Help documentation: 

    README - https://github.com/patelsamirj111/decolyzer/blob/main/README.md

    github package files - https://github.com/patelsamirj111/decolyzer
"""

setup(
    name = 'decolyzer',
    packages = ['decolyzer'],
    version = '1.5',
    license='MIT',
    description = 'decolyzer package includes functions (e.g. decorator function) which can help to enhance your own function implementation',
    long_description = long_description,
    long_description_content_type = 'text/x-rst',
    author = 'Samir',
    author_email = 'samir198@gmail.com',
    url = 'https://github.com/patelsamirj111',
    download_url = 'https://github.com/patelsamirj111/decolyzer/archive/refs/tags/v1.5.tar.gz',
    keywords = ['decorator', 'python', 'wireshark', 'scp', 'tcpdump', 'paramiko', 'ssh', 'process'],
    install_requires=[
        'paramiko',
        'pyshark',
        'scp',
    ],
    classifiers=[
        'Development Status :: 5 - Production/Stable',
        'Intended Audience :: Developers',
        'Topic :: Software Development :: Build Tools',
        'License :: OSI Approved :: MIT License',
        'Programming Language :: Python :: 3.6',
        'Programming Language :: Python :: 3.7',
        'Programming Language :: Python :: 3.8',
        'Programming Language :: Python :: 3.9',
        'Programming Language :: Python :: 3.10',
        'Programming Language :: Python :: 3.11',
        'Programming Language :: Python :: 3.12',
    ],
)
