import argparse
from collections import Counter
import json
import string

def parse_data(file_path):
    char_count = Counter()
    bigram_count = Counter()
    trigram_count = Counter()
    quadgram_count = Counter()
    start_char_count = Counter()
    end_char_count = Counter()

    with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
        for line in f:
            password = line.strip()
            if not password:
                continue
            char_count.update(password)
            bigrams = [password[i:i+2] for i in range(len(password)-1)]
            bigram_count.update(bigrams)
            trigrams = [password[i:i+3] for i in range(len(password)-2)]
            trigram_count.update(trigrams)
            quadgrams = [password[i:i+4] for i in range(len(password)-3)]
            quadgram_count.update(quadgrams)
            start_char_count.update(password[0])
            end_char_count.update(password[-1])

    return char_count, bigram_count, trigram_count, quadgram_count, start_char_count, end_char_count

def calculate_weights(counts):
    total = sum(counts.values())
    return {item: freq / total for item, freq in counts.items()}

def display_top_n(counts, weights, n=10):
    print(f"{'Item':<10} {'Count':<10} {'Weight'}")
    print('-' * 30)
    for item, count in counts.most_common(n):
        print(f"{item:<10} {count:<10} {weights[item]:.6f}")

def get_top_n(counts, weights, n=10):
    return {item: weights[item] for item, _ in counts.most_common(n)}

def filter_printable_characters(weights, threshold=0.0001):
    printable_chars = {char: weight for char, weight in sorted(weights.items(), key=lambda x: -x[1])
                       if char in string.printable and weight >= threshold}
    return printable_chars

def gramify(file_path, top_n=10):
    char_count, bigram_count, trigram_count, quadgram_count, start_char_count, end_char_count = parse_data(file_path)

    char_weights = calculate_weights(char_count)
    bigram_weights = calculate_weights(bigram_count)
    trigram_weights = calculate_weights(trigram_count)
    quadgram_weights = calculate_weights(quadgram_count)
    start_char_weights = calculate_weights(start_char_count)
    end_char_weights = calculate_weights(end_char_count)

    print(f'"\nTop {top_n} Characters:"')
    display_top_n(char_count, char_weights, top_n)

    print(f'"\nTop {top_n} Starting Characters:"')
    display_top_n(start_char_count, start_char_weights, top_n)

    print(f'"\nTop {top_n} Ending Characters:"')
    display_top_n(end_char_count, end_char_weights, top_n)

    print(f'"\nTop {top_n} Bigrams:"')
    display_top_n(bigram_count, bigram_weights, top_n)

    print(f'"\nTop {top_n} Trigrams:"')
    display_top_n(trigram_count, trigram_weights, top_n)

    print(f'"\nTop {top_n} Quadgrams:"')
    display_top_n(quadgram_count, quadgram_weights, top_n)

    data = {
        "characters": filter_printable_characters(char_weights),
        "starting_chars": get_top_n(start_char_count, start_char_weights, top_n),
        "ending_chars": get_top_n(end_char_count, end_char_weights, top_n),
        "bigrams": get_top_n(bigram_count, bigram_weights, top_n),
        "trigrams": get_top_n(trigram_count, trigram_weights, top_n),
        "quadgrams": get_top_n(quadgram_count, quadgram_weights, top_n)
    }

    with open('grams.json', 'w') as f:
        json.dump(data, f, indent=4)
    print("N-gram analysis complete. Output saved to grams.json.")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Analyze character and n-gram frequencies.")
    parser.add_argument("file_path", type=str, help="Path to the input file")
    parser.add_argument("--top_n", type=int, default=10, help="Number of top results to display and save for n-grams")

    args = parser.parse_args()
    gramify(args.file_path, args.top_n)

