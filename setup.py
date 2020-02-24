import setuptools

with open("README.md", "r") as fh:
    long_description = fh.read()


setuptools.setup(
    name='multisig-hmac',  
    version='0.2.1',
    author="Amalie Due Jensen",
    author_email="amalieduejensen@hotmail.com",
    description="multisig HMAC",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/AmalieDue/multisig-hmac-python-version",
    packages=setuptools.find_packages(),
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: ISC License (ISCL)",
        "Operating System :: OS Independent",
    ],
)