# Libraries
import umap
import hdbscan
import seaborn as sns
import matplotlib.pyplot as plt
import pandas as pd
import os
from config import DATA_PATH, RESULT_PATH


# Functions
def main() -> None:
    """
    Main function to analyse the data via UMAP and HDBSCAN clustering.
    :return: None. Save the plot to a png file
    """
    # Load the data
    features_df = pd.read_csv(os.path.join(DATA_PATH, 'features.csv'))

    # standardize the data
    features_df = (features_df - features_df.mean()) / features_df.std()

    # Perform dimensionality reduction via UMAP
    umap_model = umap.UMAP()
    embedding = umap_model.fit_transform(features_df)

    # Perform clustering via HDBSCAN on the reduced data
    clusterer = hdbscan.HDBSCAN(min_cluster_size=10)
    cluster_labels = clusterer.fit_predict(embedding)

    features_df['cluster'] = cluster_labels

    sns.scatterplot(
        x=embedding[:, 0],
        y=embedding[:, 1],
        hue=cluster_labels,
        palette='viridis',
    )
    plt.title('HDBSCAN clustering with dimensionality reduction', fontsize=16)
    plt.xlabel('UMAP 1', fontsize=12)
    plt.ylabel('UMAP 2', fontsize=12)
    # remove ticks, since it's not meaningful here
    plt.tick_params(
        axis='both',
        which='both',
        bottom=False,
        left=False,
        labelbottom=False,
        labelleft=False
    )
    plt.savefig(os.path.join(RESULT_PATH, 'hdbscan.png'))
    plt.show()

    # print the number of clusters
    print(f'Estimated number of clusters: {len(set(cluster_labels)) - (1 if -1 in cluster_labels else 0)}')

    # save the data to a csv file
    features_df.to_csv(os.path.join(RESULT_PATH, 'hdb_labels.csv'), index=False)


# Driver code:
if __name__ == '__main__':
    main()
