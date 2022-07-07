#!/usr/bin/env python3.9
# -*- coding: utf-8 -*-

import secrets
import string
import itertools
from typing import Union

DEFAULT_PW_CHARS: str = string.ascii_letters + string.digits + string.punctuation


def is_valid_input(min_pw_len: int, max_pw_len: int, pw_chars: Union[str, list[str]]) -> bool:
    """ validate the input for the below functions """

    # CHECK TYPE
    if not isinstance(min_pw_len and max_pw_len, int) or not hasattr(pw_chars, '__iter__'):
        raise TypeError('invalid type for pw len or pw charset')

    if False in [isinstance(char, str) for char in pw_chars]:
        raise TypeError('pw charset dose NOT only contains characters')

    # CHECK VALUE
    if min_pw_len < 1 or len(pw_chars) < 1:
        raise ValueError('invalid value for pw len or pw charset')

    if min_pw_len > max_pw_len:
        raise ValueError('min pw len is grater than max pw len')

    return True


def password_creator(pw_len: int = 40, pw_chars: Union[str, list[str]] = DEFAULT_PW_CHARS) -> str:
    """
    this function generates a password,
    which was created with the highest cryptographic randomness of the operating system
    """
    """ class secrets.SystemRandom
    A class for generating random numbers using the highest-quality sources provided by the operating system. 
    See random.SystemRandom for additional details.
    """

    if not is_valid_input(min_pw_len=pw_len, max_pw_len=pw_len, pw_chars=pw_chars):
        raise SystemExit('invalid input')

    return ''.join(secrets.SystemRandom(None).choice(pw_chars) for _ in range(pw_len))


def generate_all_password_combinations(min_pw_len: int = 4, max_pw_len: int = 5, pw_chars: Union[str, list[str]] = DEFAULT_PW_CHARS) -> str:
    """
    a generator function that generates all possible variations of the selected characters with repetition
    to create passwords of different lengths
    """

    if not is_valid_input(min_pw_len=min_pw_len, max_pw_len=max_pw_len, pw_chars=pw_chars):
        raise SystemExit('invalid input')

    for index in range(min_pw_len, max_pw_len):
        for password in itertools.combinations_with_replacement(pw_chars, index):
            yield ''.join(password)


def dictionary_attack(dict_file_name: str = 'rockyou.txt') -> str:
    """ yield/return the passwords contained in the given dict password file """

    try:
        with open(dict_file_name, 'r') as dict_file:
            for entry in dict_file.readlines():
                password: str = entry.strip()
                yield password

    except Exception as err:
        print(f'Error: {err}')


def calculate_all_possible_password_combinations(min_pw_len: int, max_pw_len: int, pw_chars: Union[str, list[str]]) -> int:
    """ calculates the power of the key space """

    if not is_valid_input(min_pw_len=min_pw_len, max_pw_len=max_pw_len, pw_chars=pw_chars):
        raise SystemExit('invalid input')

    return sum([pow(len(pw_chars), k) for k in range(min_pw_len, max_pw_len)])


def main() -> None:
    # password generator
    print('PASSWORD GENERATOR')
    print(password_creator(pw_len=32, pw_chars=DEFAULT_PW_CHARS))

    # generate all possible password combinations
    print('GENERATE ALL POSSIBLE PASSWORD COMBINATIONS')
    for pw in generate_all_password_combinations(min_pw_len=2, max_pw_len=3, pw_chars='abc'):
        print(pw)

    # loop over every password in a password dictionary file
    print('LOOP OVER EVERY PASSWORD IN A DICTIONARY FILE')
    for pw in dictionary_attack('rockyou.txt'):
        print(pw)

    # calculate all possible password combinations for the given charset and the given range
    print('CALCULATE POWER OF KEY SPACE')
    print(calculate_all_possible_password_combinations(min_pw_len=2, max_pw_len=5, pw_chars='abc'))


if __name__ == '__main__':
    main()    
