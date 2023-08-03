import requests
import validators
import app.constants

def make_get_request(url: str) -> requests.Response:
    validation_result = validators.url(url)
    if isinstance(validation_result, validators.ValidationFailure):
        raise ValueError('Bad url input!')
    if isinstance(validation_result, bool):
        if validation_result:
            try:
                response = requests.get(url, verify=False, headers={
                    'User-Agent': app.constants.USER_AGENT
                })
                if isinstance(response, requests.Response):
                    return response
                else:
                    raise ValueError('Bad response!')
            except requests.exceptions.ConnectionError:
                print('requests.exceptions.ConnectionError!')
            except requests.exceptions.Timeout:
                print('requests.exceptions.Timeout!')
            except requests.exceptions.RequestException:
                print('requests.exceptions.RequestException!')
