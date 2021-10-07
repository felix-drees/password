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

    :param pw_len: the desired password length
    :param pw_chars: the desired / allowed characters for creating the password
    :return: the created password
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

    :param min_pw_len: minimum password length
    :param max_pw_len: maximum password length
    :param pw_chars: the desired / allowed characters for creating the password
    :return: all possible passwords
    """

    if not is_valid_input(min_pw_len=min_pw_len, max_pw_len=max_pw_len, pw_chars=pw_chars):
        raise SystemExit('invalid input')

    for index in range(min_pw_len, max_pw_len):
        for password in itertools.combinations_with_replacement(pw_chars, index):
            yield ''.join(password)


def calculate_all_possible_password_combinations(min_pw_len: int, max_pw_len: int, pw_chars: Union[str, list[str]]) -> int:
    """
    calculates the power of the key space

    :param min_pw_len: minimum password length
    :param max_pw_len: maximum password length
    :param pw_chars: the desired / allowed characters for creating the password
    :return: the power of the key space
    """

    if not is_valid_input(min_pw_len=min_pw_len, max_pw_len=max_pw_len, pw_chars=pw_chars):
        raise SystemExit('invalid input')

    return sum([pow(len(pw_chars), k) for k in range(min_pw_len, max_pw_len)])


if __name__ == '__main__':
    # password generator
    print(password_creator(pw_len=32, pw_chars=DEFAULT_PW_CHARS), '\n')

    # generate all possible password combinations
    my_password_generator = generate_all_password_combinations(min_pw_len=2, max_pw_len=3, pw_chars=DEFAULT_PW_CHARS)
    for _ in range(10):
        print(next(my_password_generator))

    """ - OR. - 
    for pw in generate_all_password_combinations(min_pw_len=2, max_pw_len=3, pw_chars='abcde'):
        print(pw)
    """

    # calculate all possible password combinations for the given charset and the given range
    print('\n', calculate_all_possible_password_combinations(min_pw_len=2, max_pw_len=5, pw_chars='abc'))
