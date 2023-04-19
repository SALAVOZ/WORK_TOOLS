import argparse
import csv
import random
import time
import requests
import vk_api

fake_people_count = 0
'''
Получаем  access_token'ы
'''
def generate_tokens(login, password, count_of_token):
    tokens = []
    with open('tokens', 'w') as file:
        for i in range(0, count_of_token):
            VK = vk_api.VkApi(login, password, captcha_handler=captcha_handler)
            VK.auth(reauth=True)
            try:
                VK = vk_api.VkApi(login, password,captcha_handler=captcha_handler)
                VK.auth(reauth=True)
            except vk_api.exceptions.AuthError:
                print('Error while auth')
            tokens.append(VK.token['access_token'])
            print('=' * 85)
            print(f'Got {i + 1}/{count_of_token}')
            print('=' * 85)
            print(f'Access_Token: {VK.token["access_token"]}')
            print('=' * 85)
            if i == (count_of_token - 1):
                print('\n' * 3)
                try:
                    VK = VK.get_api()
                    user = VK.users.get()
                except:
                    print('Error while banner')
                else:
                    print('Hello, ', user[0]['first_name'], user[0]['last_name'])
                return tokens
            time_to_pass = random.randint(4, 8)
            print(f'Waiting {time_to_pass} seconds to bypass the captcha')
            time.sleep(time_to_pass)
    '''
    #АНАЛОГИЧНЫЙ ВАРИАНТ ПОЛУЧЕНИЯ ТОКЕНОВ
    VK = vk_api.VkApi(login, password)
    VK.auth(reauth=True)
    VK = VK.get_api()
    access_token = 0
    try:
        user = VK.users.get()
    except:
        print('Error while users.get')
    else:
        print('Hello, ', user[0]['first_name'], user[0]['last_name'])
        with open('vk_config.v2.json', 'r') as data_file:
            data = json.load(data_file)

        for xxx in data[login]['token'].keys():
            for yyy in data[login]['token'][xxx].keys():
                access_token = data[login]['token'][xxx][yyy]['access_token']
                file.write(access_token + '\n')
        print('=' * 85)
        print(f'Got {i + 1}/{count_of_token}')
        print('=' * 85)
        print(f"Access_Token: {access_token}")
        print('=' * 85)
    time.sleep(random.randint(3,8))
    '''


def build_url_get_people_by_job(job, token, age):
    code = 'API.users.search({{\'company\':\'{}\',\'sex\':0,\'fields\':\'occupation\',\'age_from\':\'{}\',\'age_to\':\'{}\',\'count\':1000}})'.format(
        job, age, age + 1)
    url = 'https://api.vk.com/method/execute?access_token={}&v=5.101&code=return%20[{}];'.format(token, code)
    return url


def get_request_people_by_age(url, job):
    global fake_people_count
    id_list = []
    result_control = True
    while result_control:
        response = requests.get(url).json()
        if 'error' in response:
            continue
        response = response['response'][0]
        count, people = response['count'], response['items']
        result_control = False
        for person in people:
            if 'occupation' in person:
                if job.upper() in person['occupation']['name'].replace('\'', '').replace('\"', '').replace('«', '').replace('»', '').upper().split():
                    id_list.append([person['id'], person['first_name'], person['last_name'], person['occupation']['name']])
                    continue
                print('Fake', person['first_name'], person['last_name'], person['occupation']['name'])
                fake_people_count += 1
            else:
                print('Fake', person['first_name'], person['last_name'])
                fake_people_count += 1
    return id_list


def captcha_handler(captcha):
    key = input("Enter captcha code {0}: ".format(captcha.get_url())).strip()
    return captcha.try_again(key)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Write args: ')
    parser.add_argument('-j', '--job', type=str, required=True, help='Write job place')
    parser.add_argument('-t', '--tokens', type=int, required=True, help='Write count of tokens')
    parser.add_argument('-l', '--login', type=str, required=True, help='Write your login')
    parser.add_argument('-p', '--password', type=str, required=True, help='Write your password')
    parser.add_argument('-f', '--file', type=str, required=True, help='Write name of output csv file')
    args = parser.parse_args()

    job = args.job.replace('\'', '').replace('\"', '')
    login = args.login.replace('\'', '').replace('\"', '')
    password = args.password.replace('\'', '').replace('\"', '')
    file_name = args.file.replace('\'', '').replace('\"', '')
    if not ('.csv' in file_name[-4:]):
        print('Write valid file name')
        exit(-1)
    count_of_tokens = args.tokens

    tokens = generate_tokens(login, password, count_of_tokens)
    print('Searching started')
    people_result = [get_request_people_by_age(url, job) for url in [build_url_get_people_by_job(job, random.choice(tokens), age) for age in range(0, 100, 2)]]
    count = 0
    csv_file = open(file_name, 'a', newline='')
    writer = csv.writer(csv_file)
    for people_list in people_result:
        for person in people_list:
            writer.writerow([person[0],person[1], person[2], person[3]])
            count += 1
    print('count of found people', count)
    print('count of fake people', fake_people_count)
    #   3832
