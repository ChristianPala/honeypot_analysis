# Libraries:
import re
import numpy as np
from nltk.tokenize import WordPunctTokenizer
from sklearn.feature_extraction.text import HashingVectorizer
import pandas as pd
import os
import matplotlib.pyplot as plt
from sklearn.cluster import DBSCAN
import umap
from config import RESULT_PATH, DATA_PATH
from typing import Tuple


# Functions:
def preprocessor(x):
    """
    Preprocess the data by identifying and replacing IP addresses, URLs, ports, ssh keys, passwords and directories
    with special tokens to improve the clustering.
    """
    # Define replacements
    replacements = [
        (r"(?:[0-9]{1,3}\.){3}[0-9]{1,3}", "IPADDRESS"),
        (r"http[s]?://(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\\(\\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+", "URL"),
        (r'(?<=:)[0-9]{1,5}\b', "PORT"),
        (r'(?<=ssh-rsa )[A-Za-z0-9+/=]+', "SSHKEY"),
        (r'(?<=echo \\"root:)[^\\]+(?=\\")', "PASSWORD"),
        (r'(?<=cd )[\w./-]+', "DIRECTORY"),
        (r'(?<=ls )[\w./-]+', "DIRECTORY"),
        (r'(?<=mv )[\w./-]+', "DIRECTORY"),
        (r'(?<=cp )[\w./-]+', "DIRECTORY"),
        (r'(?<=useradd -m )[\w./-]+', "USERNAME"),
        (r"(/[^/ ]*)+/?", "FILEPATH"),
        (r"sh -c", "SHSCRIPT")
    ]

    # Apply replacements
    for pattern, repl in replacements:
        x = re.sub(pattern, repl, x)

    return x


def tokenize_commands(nr_features: int = 1000) -> HashingVectorizer:
    """
    Tokenize the commands using the WordPunctTokenizer from nltk.
    :param nr_features: The number of features to extract with the HashingVectorizer
    :return: None. Save the data to a csv file
    """
    # Load the data
    df = pd.read_csv(os.path.join(DATA_PATH, 'commands.csv'))
    X = df['commands'].values

    # Tokenize the commands
    wpt = WordPunctTokenizer()
    hvwpt = HashingVectorizer(
        lowercase=False,
        preprocessor=preprocessor,
        tokenizer=wpt.tokenize,
        token_pattern=None,
        n_features=nr_features
    )

    return hvwpt.fit_transform(X)


def dbscan_cluster() -> Tuple[DBSCAN, HashingVectorizer]:
    """
    Cluster the data using DBSCAN from sklearn.
    :return: None. Save the data to a csv file
    """
    model = DBSCAN(eps=0.5, min_samples=5)
    x = tokenize_commands()
    model.fit(x)
    # Cluster labels
    labels = model.labels_
    # Number of clusters in labels, ignoring noise if present.
    n_clusters_ = len(set(labels)) - (1 if -1 in labels else 0)
    print(f'Estimated number of clusters: {n_clusters_}')
    return model, x


def plot_dbscan(model: DBSCAN, data: np.array) -> None:
    """
    Plot the clusters using PCA for dimensionality reduction.
    :param model: The DBSCAN model
    :param data: The vectorized commands data
    :return: None. Save the plot to a png file
    """
    # Reduce dimensions with UMAP:
    reducer = umap.UMAP()
    reduced_data = reducer.fit_transform(data)
    # Get labels
    labels = model.labels_
    # Create a scatter plot
    plt.figure(figsize=(8, 6))
    plt.scatter(reduced_data[:, 0], reduced_data[:, 1], c=labels, cmap='viridis')
    plt.title('DBSCAN clustering with dimensionality reduction', fontsize=16)
    plt.xlabel('UMAP 1', fontsize=12)
    plt.ylabel('UMAP 2', fontsize=12)
    # remove ticks, since it's not meaningful here
    plt.tick_params(axis='both', which='both', bottom=False, top=False, labelbottom=False, right=False, left=False,
                    labelleft=False)
    plt.colorbar(label='Cluster labels')
    # Save the plot
    plt.savefig(os.path.join(RESULT_PATH, 'dbscan_plot.png'))
    plt.show()

    # Save the labels to a csv file
    df = pd.DataFrame(labels, columns=['cluster'])

    # Save the data to a csv file
    df.to_csv(os.path.join(RESULT_PATH, 'dbscan_labels.csv'), index=False)
    # Noise points
    n_noise_ = list(labels).count(-1)
    print(f'Estimated number of noise points: {n_noise_}')


def main() -> None:
    """
    Main function.
    :return: None. Save the data to a csv file
    """
    plot_dbscan(*dbscan_cluster())


# Driver code:
if __name__ == '__main__':
    main()

