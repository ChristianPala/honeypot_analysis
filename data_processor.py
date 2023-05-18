# Load the honey-pot data from the csv files provided by professor Consoli and save it to a single csv file
# Libraries:
import re
from datetime import datetime
import pandas as pd
import glob
from config import DATA_PATH
import os
import logging


# Functions:
def parse_csv_line(line):
    """
    Function to parse a line from the csv files with timestamp and shell commands.
    @param line: The line to parse
    :return: A DataFrame with the timestamp and commands as columns.
    """
    # Regular expression to match timestamp and command, which are separated by ","
    match = re.match(r'"(.*?)","(.*)"', line)
    if match:
        timestamp = match.group(1)
        commands = match.group(2)

        # Convert the timestamp to a datetime object
        timestamp = int(timestamp) / 1000.
        date = datetime.fromtimestamp(timestamp)

        return pd.DataFrame([[date, commands]], columns=['date', 'commands'])
    else:
        return pd.DataFrame()


def process_data() -> None:
    """
    Load the honey-pot data from the csv files and save it to a single csv file
    :return: None. Save the data to a csv file
    """
    file_name_pattern = os.path.join(DATA_PATH, 'sample_commands_w*.csv')

    # Use glob to match the pattern 'sample_commands_w*.csv'
    files = glob.glob(file_name_pattern)

    df_list = []

    total_lines = 0
    for file in files:
        with open(file, 'r') as f:
            lines = f.readlines()

        total_lines += len(lines)

        for line in lines:
            df_list.append(parse_csv_line(line))

    df = pd.concat(df_list, ignore_index=True)

    # sort the DataFrame by date
    df = df.sort_values(by=['date'])

    # Ensure that all lines have been parsed correctly
    if len(df) == total_lines:
        print("All lines have been parsed correctly.")
    else:
        logging.warning("Not all lines have been parsed correctly.")
        print(f"Total lines: {total_lines}")
        print(f"Lines parsed: {len(df)}")

    # save the DataFrame to a csv file
    df.to_csv(os.path.join(DATA_PATH, 'commands.csv'), index=False)


if __name__ == '__main__':
    logging.basicConfig(level=logging.INFO)
    process_data()