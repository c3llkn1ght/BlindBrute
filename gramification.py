import argparse
from collections import Counter
import json
import string
import re

def parse_data(file_path, type='char'):
    char_count = Counter()
    bigram_count = Counter()
    trigram_count = Counter()
    quadgram_count = Counter()

    if type == 'char':
        start_unit_count = Counter()
        end_unit_count = Counter()
    else:
        start_unit_count = end_unit_count = None

    with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
        content = f.read()
        tokens = re.split(r'[,\s]+', content)
        tokens = [token.strip() for token in tokens if token.strip()]

        if type == 'char':
            for token in tokens:
                char_count.update(token)
                start_unit_count.update(token[0])
                end_unit_count.update(token[-1])
                bigrams = [token[i:i+2] for i in range(len(token)-1)]
                bigram_count.update(bigrams)
                trigrams = [token[i:i+3] for i in range(len(token)-2)]
                trigram_count.update(trigrams)
                quadgrams = [token[i:i+4] for i in range(len(token)-3)]
                quadgram_count.update(quadgrams)
        elif type == 'word':
            char_count.update(tokens)
            bigrams = [' '.join(tokens[i:i+2]) for i in range(len(tokens)-1)]
            bigram_count.update(bigrams)
            trigrams = [' '.join(tokens[i:i+3]) for i in range(len(tokens)-2)]
            trigram_count.update(trigrams)
            quadgrams = [' '.join(tokens[i:i+4]) for i in range(len(tokens)-3)]
            quadgram_count.update(quadgrams)

    return char_count, bigram_count, trigram_count, quadgram_count, start_unit_count, end_unit_count

def calculate_weights(counts):
    total = sum(counts.values())
    return {item: freq / total for item, freq in counts.items()} if total > 0 else {}

def display_top_n(counts, weights, n=10):
    print(f"{'Item':<30} {'Count':<10} {'Weight'}")
    print('-' * 50)
    for item, count in counts.most_common(n):
        print(f"{item:<30} {count:<10} {weights.get(item, 0):.6f}")

def get_top_n(counts, weights, n=10):
    return {item: weights.get(item, 0) for item, _ in counts.most_common(n)}

def filter_printable_items(weights, threshold=0.0001):
    printable_items = {
        item: weight
        for item, weight in sorted(weights.items(), key=lambda x: -x[1])
        if all(c in string.printable for c in item) and weight >= threshold
    }
    return printable_items

def gramify(file_path, top_n=10, type='char'):
    counts = parse_data(file_path, type)
    char_count, bigram_count, trigram_count, quadgram_count, start_unit_count, end_unit_count = counts

    char_weights = calculate_weights(char_count)
    bigram_weights = calculate_weights(bigram_count)
    trigram_weights = calculate_weights(trigram_count)
    quadgram_weights = calculate_weights(quadgram_count)

    if type == 'char':
        start_unit_weights = calculate_weights(start_unit_count)
        end_unit_weights = calculate_weights(end_unit_count)
        unit_label = 'Character'
        start_label = 'Starting Characters'
        end_label = 'Ending Characters'
    else:
        unit_label = 'Word'

    print(f"\nTop {top_n} {unit_label}s:")
    display_top_n(char_count, char_weights, top_n)

    if type == 'char':
        print(f"\nTop {top_n} {start_label}:")
        display_top_n(start_unit_count, start_unit_weights, top_n)

        print(f"\nTop {top_n} {end_label}:")
        display_top_n(end_unit_count, end_unit_weights, top_n)

    print(f"\nTop {top_n} Bigrams:")
    display_top_n(bigram_count, bigram_weights, top_n)

    print(f"\nTop {top_n} Trigrams:")
    display_top_n(trigram_count, trigram_weights, top_n)

    print(f"\nTop {top_n} Quadgrams:")
    display_top_n(quadgram_count, quadgram_weights, top_n)

    data = {
        f"{"words" if type=="word" else "characters"}": filter_printable_items(char_weights),
        "bigrams": get_top_n(bigram_count, bigram_weights, top_n),
        "trigrams": get_top_n(trigram_count, trigram_weights, top_n),
        "quadgrams": get_top_n(quadgram_count, quadgram_weights, top_n)
    }

    if type == 'char':
        data["starting_chars"] = get_top_n(start_unit_count, start_unit_weights, top_n)
        data["ending_chars"] = get_top_n(end_unit_count, end_unit_weights, top_n)

    with open('grams.json', 'w') as f:
        json.dump(data, f, indent=4)
    print("N-gram analysis complete. Output saved to grams.json.")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Analyze character or word n-gram frequencies.")
    parser.add_argument("file_path", type=str, help="Path to the input file")
    parser.add_argument("--top-n", type=int, default=10, help="Number of top results to display and save for n-grams")
    parser.add_argument("--type", type=str, choices=['char', 'word'], default='char', help="Type of n-grams to analyze: 'char' for character n-grams, 'word' for word n-grams")

    args = parser.parse_args()
    gramify(args.file_path, args.top_n, args.type)
