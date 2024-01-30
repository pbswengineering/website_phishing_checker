<a href="https://www.bernardi.cloud/">
    <img src=".readme-files/logo-72.png" alt="Website Phishing Checker" title="Website Phishing Checker" align="right" height="72" />
</a>

# Website Phishing Checker
> Proof of concept of an AI-powered phishing website classifier

[![Python](https://img.shields.io/badge/python-v3.7+-blue.svg)](https://www.python.org)
[![License](https://img.shields.io/badge/License-BSD_2--Clause-orange.svg)](https://opensource.org/licenses/BSD-2-Clause)
[![GitHub issues](https://img.shields.io/github/issues/pbswengineering/website_phishing_checker.svg)](https://github.com/pbswengineering/website_phishing_checker/issues)

## Table of contents

- [What is Website Phishing Checker](#what-is-website-phishing-checker)
- [Usage](#usage)
- [License](#license)
- [Credits](#credits)

## What is Website Phishing Checker

Website Phishing Checker is a Python command line application that reads an URL in input and tries to classify it as phishing or NOT phishing.

## Usage

Firstly you need to install all required libraries, possibly in a Virtual Environment:

  pip install -r requirements.txt

Finally you can just run the checker like this:

  python check.py

## License

Website Phishing Checker is licensed under the terms of the 2-clauses BSD license.

## Credits

  - The dataset is proveded by the UCI Machine Learning Repository: [https://doi.org/10.24432/C52W2X](https://doi.org/10.24432/C52W2X)
  - Phishing domains database by Mitchell Krog: [https://github.com/mitchellkrogza/Phishing.Database/](https://github.com/mitchellkrogza/Phishing.Database/)