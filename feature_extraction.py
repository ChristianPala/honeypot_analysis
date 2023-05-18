# Libraries:
import pandas as pd
import os
import re
import logging
from config import DATA_PATH
from typing import List, Tuple


# Functions
def compile_patterns() -> dict:
    """
    Compile all necessary regex patterns to extract information, and return them in a dictionary. Patterns
    are pre-compiled for efficiency.
    :return: A dictionary where keys are pattern names and values are the compiled regex patterns.
    """
    command_patterns = {
        'system_info_gathering': re.compile('|'.join([
            r'uname',  # OS, kernel, and machine name
            r'hostname',  # hostname
            r'uptime',  # system uptime
            r'lsb_release -a',  # full system info
            r'cat \/etc\/issue',  # system release info
            r'dmesg',  # print or control the kernel ring buffer
            # ...
        ])),
        'network_info_gathering': re.compile('|'.join([
            r'ifconfig',  # network interface configuration
            r'ip addr',  # IP address info
            r'netstat',  # network statistics
            r'route',  # routing tables
            r'ss -tuln',  # list open ports
            r'arp',  # arp table
            r'nmap',  # network exploration tool and security / port scanner
            # ...
        ])),
        'user_info_gathering': re.compile('|'.join([
            r'whoami',  # current user
            r'w',  # who is logged in and what they are doing
            r'last',  # listing of last logged in users
            r'cat \/etc\/passwd',  # list of system users
            # ...
        ])),
        'file_info_gathering': re.compile('|'.join([
            r'ls',  # list directory contents
            r'find',  # search for files in a directory hierarchy
            r'cat \/etc\/fstab',  # default system mounts
            r'df -h',  # disk space usage of file system
            r'du -sh',  # estimate file and directory space usage
            # ...
        ])),
        'running_processes_info_gathering': re.compile('|'.join([
            r'ps',  # process status
            r'top',  # display Linux processes
            r'pstree',  # display a tree of processes
            r'lsof',  # list open files
            # ...
        ])),
        'privilege_escalation': re.compile('|'.join([
            r'chpasswd',  # chpasswd command
            r'passwd',  # passwd command
            r'chsh',  # chsh command
            r'chfn',  # chfn command
            r'chage',  # chage command
            r'chmod',  # chmod command
            r'chown',  # chown command
            r'chgrp',  # chgrp command
            r'usermod',  # usermod command
            r'useradd',  # useradd command
            r'userdel',  # userdel command
            r'groupmod',  # groupmod command
            r'groupadd',  # groupadd command
            r'groupdel',  # groupdel command
            r'newgrp',  # newgrp command
            r'newusers',  # newusers command
            r'gpasswd',  # gpasswd command
            # ...
        ])),
        'execution_attempt': re.compile('|'.join([
            r'\bchmod +x\b', r'\.sh\b', r'\.py\b', r'\.pl\b', r'\.php\b', r'\.exe\b',
            r'\.bin\b', r'\.elf\b', r'\.sh\b', r'\.bash\b', r'\.c\b', r'\.cpp\b', r'\.java\b'
        ])),
        'network_communication': re.compile('|'.join([
            r'\bwget\b', r'\bcurl\b', r'\bssh\b', r'\bftp\b', r'\bnc\b', r'\bping\b',
            r'\btelnet\b', r'\bnetcat\b', r'\bscp\b', r'\bsftp\b'
        ])),
        'admin_commands': re.compile('|'.join([
            r'\bsudo\b', r'\bvisudo\b', r'\bchown\b', r'\bchgrp\b', r'\busermod\b',
            r'\buseradd\b', r'\buserdel\b', r'\bgroupadd\b', r'\bgroupdel\b', r'\bgroupmod\b',
            r'\bchmod\b', r'\bchroot\b', r'\bmkfs\b', r'\bmke2fs\b', r'\bmkswap\b',
            r'\bmount\b', r'\bumount\b', r'\bfsck\b', r'\bapt-get\b', r'\byum\b',
            r'\bdpkg\b', r'\bapt\b', r'\baptitude\b', r'\byum\b', r'\bzypper\b',
            r'\byast\b', r'\brpm\b', r'\bsu\b', r'\bdoas\b', r'\bbecome\b'
        ])),
        # Excluded since no examples were found in the dataset
        # 'crypto_mining_detection': re.compile('|'.join([
        #     r'xmrig',  # common mining software
        #     r'cgminer',  # common mining software
        #     r'bfgminer',  # common mining software
        #     r'ethminer',  # common mining software
        #     r'minerd',  # common mining software
        #     r'cpuminer',  # common mining software
        #     r'stratum\+tcp',  # common protocol for mining pools
        #     r'bc1[a-zA-HJ-NP-Z0-9]{25,39}',  # Bitcoin wallet addresses (Bech32)
        # ]))
    }

    # Other compiled regex patterns
    other_patterns = {
        'ip': re.compile(r'\b((?:[0-9]{1,3}\.){3}[0-9]{1,3})\b'),
        'port': re.compile(r'(?<=:)[0-9]{1,5}\b'),
        'url': re.compile(r'http[s]?://(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\\(\\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+'),
        'directory': [re.compile(pattern) for pattern in [
            r'(?<=cd )[^ ]+',
            r'(?<=ls )[^\-][^ ]+',
            r'(?<=cat )[^\-][^ ]+',
            r'(?<=mv )[^\-][^ ]+',
            r'(?<=cp )[^\-][^ ]+'
        ]],
        'ssh_key': re.compile(r'(?<=ssh-rsa )[A-Za-z0-9+/=]+'),
        'password': re.compile(r'(?<=echo \\"root:)[^\\]+(?=\\")'),
    }

    return {**command_patterns, **other_patterns}


def is_pattern(pattern: re.Pattern, command: str) -> bool:
    """
    Check if a given command exhibits a given pattern.
    @param pattern: re.Pattern: The compiled regex pattern to match.
    @param command: str: The command string to search in.
    :return: bool: True if the pattern is found, False otherwise.
    """
    return pattern.search(command) is not None


def get_match(pattern: re.Pattern, command: str) -> List[str]:
    """
    Extract matches for a given pattern from a command string.
    @param pattern: The compiled regex pattern to match.
    @param command: The command string to search.
    :return: A list of matches.
    """
    return pattern.findall(command)


def clean_extracted_elements(df: pd.DataFrame, columns: List[str]) -> pd.DataFrame:
    """
    Clean up the format of the extracted elements and remove duplicates.
    @param df: The dataframe to clean.
    @param columns: The columns to clean.
    :return: The cleaned dataframe.
    """
    for column in columns:
        # Remove duplicates and strip whitespaces.
        df[column] = df[column].apply(lambda x: list(set(x)))
        # Remove empty strings and strip whitespaces.
        df[column] = df[column].apply(lambda x: [element for element in x if element != ''])
        df[column] = df[column].apply(lambda x: [element.strip() for element in x])

    return df


def list_to_count(df: pd.DataFrame, columns: List[str]) -> pd.DataFrame:
    """
    Convert list fields into counts, basic approach to cluster the getters.
    @param df: The dataframe to convert.
    @param columns: The columns to convert.
    :return: The converted dataframe.
    """
    for column in columns:
        df[column] = df[column].apply(len)
    return df


def check_extraction(df: pd.DataFrame) -> Tuple[bool, List[str]]:
    """
    Check if the extraction was successful for all the columns added. Success is defined as having at least 1
    non-empty value in the column.
    @param df: The dataframe to check.
    :return: True if the extraction was successful, False otherwise.
    """
    useless_columns = []
    for column in df.columns:
        if column not in ['data', 'commands']:
            if df[column].sum() == 0:
                useless_columns.append(column)
    return len(useless_columns) == 0, useless_columns


def extract_features():
    df = pd.read_csv(os.path.join(DATA_PATH, 'commands.csv'))
    patterns = compile_patterns()

    # *****************************************************************************************************************
    # Add features to the dataframe
    # Getters:
    getters = ['ip', 'port', 'url', 'new_password', 'directory', 'ssh_key']
    df['ip'] = df['commands'].apply(lambda cmd: get_match(patterns['ip'], cmd))
    df['port'] = df['commands'].apply(lambda cmd: get_match(patterns['port'], cmd))
    df['url'] = df['commands'].apply(lambda cmd: get_match(patterns['url'], cmd))
    df['new_password'] = df['commands'].apply(lambda cmd: get_match(patterns['password'], cmd))
    df['directory'] = df['commands'].apply(
        lambda cmd: [match for pattern in patterns['directory'] for match in get_match(pattern, cmd)])
    df['ssh_key'] = df['commands'].apply(lambda cmd: get_match(patterns['ssh_key'], cmd))

    df = clean_extracted_elements(df, getters)

    # Checkers:
    feature_list = ['system_info_gathering', 'network_info_gathering', 'user_info_gathering',
                    'running_processes_info_gathering', 'file_info_gathering', 'privilege_escalation',
                    'execution_attempt', 'network_communication', 'admin_commands']

    for feature in feature_list:
        df[feature] = df['commands'].apply(lambda cmd: is_pattern(patterns[feature], cmd))
    # *****************************************************************************************************************

    # Check if the extraction was successful
    success, column = check_extraction(df)
    if success:
        print('Extraction successful.')
    else:
        logging.warning(f'Extraction failed for columns: {column}')

    # Save the dataframe with the full information for the information extraction task:
    df.to_csv(os.path.join(DATA_PATH, 'extracted_information.csv'), index=False)

    # Convert the list fields into counts for the clustering task:
    df = list_to_count(df, getters)
    # Save the features to a new csv file
    features_df = df.drop(columns=['commands', 'date'])

    # cast to int
    features_df = features_df.astype(int)

    features_df.to_csv(os.path.join(DATA_PATH, 'features.csv'), index=False, header=True)

    # Check we have no missing values in the features dataframe
    if features_df.isnull().values.any():
        logging.warning('Missing values in the features dataframe.')


# Driver code
if __name__ == '__main__':
    logging.basicConfig(level=logging.INFO)
    extract_features()
