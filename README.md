# cesr-verifier
A service to verify ACDC credentials in CESR format.
This code is based on [vlei-verifier](https://github.com/GLEIF-IT/vlei-verifier)


#### Run from source

* Make sure python version is >=3.12.2.
* Setup virtual environment:
    ```bash
    python3 -m venv venv
    ```
* Activate virtual environment:
    ```bash
    source venv/bin/activate
    ```
* If required, update pip in the virtual environment:
    ```bash
    python3 -m pip install --upgrade pip
    ```
* Install dependencies:
    ```bash
    pip install -e ./
    ```
* Run verifier server:
    ```bash
    verifier server start --config-dir scripts --config-file verifier-config.json
    ```


## APIs
* GET `/health`. Example:
    ```bash
    curl GET http://localhost:7676/health -vvvv -H "Content-Type: application/json"
    ```

* PUT `/v1/cesr-verifier/presentations/{said}` with the CESR material in the body. Examples:
    ```bash
    curl -X PUT http://localhost:7676/v1/cesr-verifier/presentations/EFgXpBg0WwFqdnCV0lHfZqjP-ZAlO4XBgF1fSi8e_ZeB -vvvv -H "Content-Type: application/json+cesr" --data "@./tests/data/credential/EFgXpBg0WwFqdnCV0lHfZqjP-ZAlO4XBgF1fSi8e_ZeB.cesr"

    curl -X PUT http://localhost:7676/v1/cesr-verifier/presentations/EKLZNI1s8U0PCGG1XtjIX6VV-O6GCtdv1qpFPlEzZJuO -vvvv -H "Content-Type: application/json+cesr" --data "@./tests/data/credential/EKLZNI1s8U0PCGG1XtjIX6VV-O6GCtdv1qpFPlEzZJuO.cesr"
    ```

* POST `/v1/cesr-verifier/verifier` with the CESR material in the body. Examples:
    ```bash
    curl -X POST http://localhost:7676/v1/cesr-verifier/verifier -vvvv -H "Content-Type: application/json+cesr" --data "@./tests/data/credential/credential.cesr"
    ```

## State of the Application
This service writes data into disk as part of verifying the data. However, we will not consider it a stateful application as those are temporary data.
