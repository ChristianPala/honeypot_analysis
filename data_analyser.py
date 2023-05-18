# Libraries:
from collections import defaultdict
import socket
from urllib.parse import urlparse
import pandas as pd
import os
import matplotlib.pyplot as plt
from config import RESULT_PATH
from wordcloud import WordCloud


# Functions:
def plot_bar(df: pd.DataFrame, column: str, title: str, file_name: str) -> None:
    """
    Plot a bar chart of the given column of the given DataFrame
    @param df: pd.DataFrame: the DataFrame to plot from.
    @param column: str: the column to plot from.
    @param title: str: the title of the plot.
    @param file_name: str: the name of the file to save the plot to.
    :return: None. Save the plot to a file.
    """
    # Count the frequency of each unique value in the column
    value_counts = df[column].value_counts()

    # Create the bar plot
    value_counts.plot(kind='bar', log=True)
    plt.title(title, fontsize=16)
    plt.savefig(os.path.join(RESULT_PATH, file_name))
    plt.xticks(range(len(value_counts.index)), [x.replace('_', ' ') for x in value_counts.index], rotation=90)
    plt.xlabel("Categories")
    plt.ylabel("Frequency")
    plt.subplots_adjust(bottom=0.4)
    plt.savefig(os.path.join(RESULT_PATH, file_name))
    plt.show()


def plot_command_length(df: pd.DataFrame) -> None:
    """
    Function to plot the length of the commands.
    :return: None. Save the plot to a png file
    """
    # Plot the length of the commands
    df['command_length'] = df['commands'].apply(lambda x: len(x))
    # Log scale
    df['command_length'].hist(bins=100, log=True)
    plt.title('Command length logarithmic distribution', fontsize=16)
    plt.savefig(os.path.join(RESULT_PATH, 'command_length.png'))
    plt.show()


def plot_command_frequency(df: pd.DataFrame) -> None:
    """
    Function to plot the frequency of the commands.
    :return: None. Save the plot to a png file
    """
    # Plot the frequency of the commands
    df['commands'].value_counts()[1:].hist(bins=100, log=True)
    plt.title('Logarithmic frequency of the commands', fontsize=16)
    plt.savefig(os.path.join(RESULT_PATH, 'command_frequency.png'))
    plt.show()


def write_to_csv(df: pd.DataFrame) -> None:
    """
    Function to write the results of the extracted information to csv files.
    @param df: The DataFrame with the extracted information
    :return: None. Save the results to csv files
    """
    # Write the results to csv files
    for column, file_name in [('ip', 'extracted_ips.csv'), ('port', 'extracted_ports.csv'),
                              ('url', 'extracted_urls.csv'), ('new_password', 'extracted_passwords.csv'),
                              ('directory', 'extracted_directories.csv'), ('ssh_key', 'extracted_ssh_keys.csv')]:
        filtered_df = df[df[column].apply(lambda x: len(x) > 0)]
        # sort the values by the frequency
        filtered_df[column].value_counts().sort_values(ascending=False).to_csv(os.path.join(RESULT_PATH, file_name),
                                                                               index=True)


def generate_word_cloud(df: pd.DataFrame, column: str, file_name: str) -> None:
    """
    Generate a word cloud from the given column of the DataFrame
    @param df: pd.DataFrame: the DataFrame to generate from.
    @param column: str: the column to generate from.
    @param file_name: str: the name of the file to save the word cloud to.
    :return: None. Save the word cloud to a file.
    """
    # Extract the top 1000 most frequent words
    text = ' '.join(df[column].value_counts()[:1000].index)

    # Generate the word cloud
    wordcloud = WordCloud(width=800, height=400).generate(text)

    # Display the word cloud
    plt.imshow(wordcloud, interpolation='bilinear')
    plt.axis("off")
    plt.savefig(os.path.join(RESULT_PATH, file_name), format='png')
    plt.show()


def categorize_commands(df: pd.DataFrame) -> pd.DataFrame:
    """
    Categorize commands into defined types
    @param df: DataFrame containing the commands
    :return: DataFrame with an additional column for the command category
    """
    # Define command categories
    categories = {
        "system_information": ["uname", "whoami", "id", "lsb_release"],
        "network_information": ["ifconfig", "ip", "netstat", "ss"],
        "file_operations": ["ls", "touch", "rm", "cp", "mv"],
        "process_operations": ["ps", "top", "kill", "pkill"],
        "user_operations": ["useradd", "userdel", "usermod", "passwd", "chpasswd", "chage"],
        "network_operations": ["ssh", "scp", "ftp", "telnet", "wget", "curl", "nc", "ncat", "netcat", "nmap"],
        "privilege_escalation": ["sudo", "su", "chown", "chmod", "chgrp", "setuid", "setgid", "setcap", "getcap"],
        "shell_operations": ["bash", "sh", "zsh", "csh", "ksh", "tcsh", "dash", "fish", "zsh", "powershell"],
        "package_management": ["apt", "apt-get", "yum", "dnf", "pip", "gem", "npm"],
        "service_operations": ["systemctl", "service", "systemd"],
        "disk_operations": ["df", "du", "fdisk", "mkfs", "mount", "umount"],
        "text_processing": ["grep", "sed", "awk", "cut", "sort", "uniq", "tr", "wc"],
        "environment_variables": ["export", "set", "unset", "env"],
        "file_search": ["find", "locate"],
        "archiving": ["tar", "gzip", "gunzip", "bzip2", "zip", "unzip"]
    }

    # Create a new column for the command category
    df["command_category"] = "other"

    # Categorize commands
    for category, commands in categories.items():
        for command in commands:
            df.loc[df["commands"].str.contains(command, regex=False), "command_category"] = category

    return df


def analyse_malicious_urls():
    """
    Analyse the malicious urls extracted from the honey-pot.
    :return: None. Save the results to csv files
    """
    df = pd.read_csv(os.path.join(RESULT_PATH, 'extracted_urls.csv'))

    # Function to check if a domain is an IP
    def is_ip(domain):
        try:
            socket.inet_aton(domain)
            return True
        except socket.error:
            return False

    # Extract and count the domains
    domain_counts = defaultdict(int)
    for urls in df['url']:
        urls = eval(urls)
        for url in urls:
            domain = urlparse(url).netloc
            if not is_ip(domain):
                domain_counts[domain] += 1

    # Create a DataFrame from the domain_counts dictionary
    domain_counts_df = pd.DataFrame(list(domain_counts.items()), columns=['Domain', 'Count'])

    # Sort the values by the frequency
    domain_counts_df = domain_counts_df.sort_values(by='Count', ascending=False)

    # Write the results to csv files
    domain_counts_df.to_csv(os.path.join(RESULT_PATH, 'extracted_domains.csv'), index=False)


def main() -> None:
    """
    Main function to analyse the data extracted from the honey-pot.
    :return: None. Save the results to csv files
    """
    # Load the data
    df = pd.read_csv(os.path.join('data', 'extracted_information.csv'))

    df = categorize_commands(df)

    # Write the results to csv files
    write_to_csv(df)
    analyse_malicious_urls()

    # Produce plots
    plot_command_length(df)
    plot_command_frequency(df)
    plot_bar(df, 'command_category', 'Command categories frequencies', 'command_categories.png')
    generate_word_cloud(df, 'commands', 'word_cloud.png')


# Driver code
if __name__ == '__main__':
    main()
