# Tool developed to help 'Pampered Pets' evaluate their threat profile.
# Utilises the OCTAVE-S framework for risk analysis.

import networkx as nx  # For graph creation
import matplotlib.pyplot as plt  # For graph visualisation
import json  # To handle and process JSON file

# Function to load the attack tree from a JSON file
def load_attack_tree_from_json(file_path):
    try:
        with open(file_path, 'r') as file:
            data = json.load(file)
        return data
    except Exception as e:
        print(f"Error loading JSON: {e}")
        return {}

# Load the data from the JSON file into tree_data
tree_data = load_attack_tree_from_json('data/digitalised.json')

# Function to calculate the PI (Probability x Impact) score for each threat
def calculate_pi_score(tree_data):
    pi_scores = {}
    for entity, details in tree_data.items():
        if "Threats" in details:
            for threat, metrics in details["Threats"].items():
                score = metrics["Probability"] * metrics["Impact"]
                pi_scores[threat] = score
    return pi_scores

# Function to determine the color of each node based on its PI score
def determine_node_colour(pi_scores):
    max_score = max(pi_scores.values())
    node_colours = {}
    for node, score in pi_scores.items():
        if score == max_score:
            node_colours[node] = "red"
        elif score >= 0.5 * max_score:  # adjusted this threshold
            node_colours[node] = "orange"
        else:
            node_colours[node] = "green"
    return node_colours

# Function to visualise the attack tree graph
def visualise_attack_tree(tree, tree_data):
    G = nx.DiGraph()

    pi_scores = calculate_pi_score(tree_data)
    node_colours_map = determine_node_colour(pi_scores)

    for parent, children in tree.items():
        if "Threats" in children:
            for child in children["Threats"]:
                G.add_edge(parent, child)

    node_colours = [node_colours_map.get(node, "green") for node in G.nodes()]

    # Use NetworkX shell layout
    shells = [list(tree.keys()), list(pi_scores.keys())]
    pos = nx.shell_layout(G, shells)

    nx.draw(G, pos, with_labels=True, node_size=3000, node_color=node_colours, arrowstyle='-|>')
    plt.show()

# Visualise the attack tree using tree_data
visualise_attack_tree(tree_data["DigitalisedRecommendations"], tree_data["DigitalisedRecommendations"])
