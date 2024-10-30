# cesr-verifier
A service to verify ACDC credentials in CESR format.
This code is based on [vlei-verifier](https://github.com/GLEIF-IT/vlei-verifier)

## Installation

```
pip install -e ./
```

## Execution

```
verifier server start --config-dir scripts --config-file verifier-config.json
```


## API
PUT `/v1/cesr-verifier/presentations/{said}` with the CESR material in the body. Examples:

```
curl -X PUT http://localhost:7676/v1/cesr-verifier/presentations/EFgXpBg0WwFqdnCV0lHfZqjP-ZAlO4XBgF1fSi8e_ZeB -vvvv -H "Content-Type: application/json+cesr" --data "@./tests/data/credential/EFgXpBg0WwFqdnCV0lHfZqjP-ZAlO4XBgF1fSi8e_ZeB.cesr"

curl -X PUT http://localhost:7676/v1/cesr-verifier/presentations/EKLZNI1s8U0PCGG1XtjIX6VV-O6GCtdv1qpFPlEzZJuO -vvvv -H "Content-Type: application/json+cesr" --data "@./tests/data/credential/EKLZNI1s8U0PCGG1XtjIX6VV-O6GCtdv1qpFPlEzZJuO.cesr"
```

## State of the Application
This service writes data into disk as part of verifying the data. However, we will not consider it a stateful application as those are temporary data.
