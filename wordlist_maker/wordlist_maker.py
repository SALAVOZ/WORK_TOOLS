import argparse
import string


def read_wordlist(wordlist):
    list_of_list_names = []
    list_of_names = []
    f = open(wordlist, 'r')
    person = 'start'
    index = 0
    while person != '':
        person = f.readline().replace('\n', '').replace(' ', '')
        index += 1
        list_of_names.append(person)
        if index % 50 == 0:
            list_of_list_names.append(list_of_names)
            list_of_names = []
    if len(list_of_names) > 0:
        list_of_list_names.append(list_of_names)
    return list_of_list_names


def create_dictionary(name):
    dict = []
    for first_letter in string.ascii_uppercase:
        for second_letter in string.ascii_uppercase:
            dict.append(name + ' ' + first_letter + '.' + second_letter + '.')
    return dict


def create_txt_dictionary(dict, file, index):
    with open(f'{index}_{file}', 'a') as f:
        for name in dict:
            res = create_dictionary(name)
            for var in res:
                f.write(var + '\n')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Write args: ')
    #parser.add_argument('-n', '--name', type=str, required=True, help='Напишите фамилию. Например, -n Petrov')
    parser.add_argument('-w', '--wordlist', type=str, required=True, help='Напишите название файла вордлиста.')
    parser.add_argument('-f', '--file', type=str, required=True, help='Напишите название словаря. Например, -f dict.txt')
    args = parser.parse_args()
    wordlist = args.wordlist.replace('\"', '').replace('\'', '')
    file = args.file.replace('\"', '').replace('\'', '')

    list_of_lists = read_wordlist(wordlist)

    for i, list in enumerate(list_of_lists, start=1):
        create_txt_dictionary(list, file, i)

    #for i in range(5):
    #    list_of_lists.append(create_dictionary(wordlist))
    #create_txt_dictionary(dictionary, file)