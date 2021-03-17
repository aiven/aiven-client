# Spelling Corrector in Python 3; see http://norvig.com/spell-correct.html
#
# Copyright (c) 2007-2016 Peter Norvig
# MIT license: www.opensource.org/licenses/mit-license.php


def suggest(word_to_check, known_words):
    def get_correction(word):
        """Most probable spelling correction for word."""
        candidates = get_candidates(word)
        return next(iter(candidates)) if candidates else None

    def get_candidates(word):
        """Generate possible spelling corrections for word."""
        return get_known([word]) or get_known(get_edits1(word)) or get_known(get_edits2(word)) or []

    def get_known(words):
        """The subset of `words` that appear in the dictionary of WORDS."""
        return set(w for w in words if w in known_words)

    def get_edits1(word):
        """All edits that are one edit away from `word`."""
        letters = "abcdefghijklmnopqrstuvwxyz_"
        splits = [(word[:i], word[i:]) for i in range(len(word) + 1)]
        deletes = [L + R[1:] for L, R in splits if R]
        transposes = [L + R[1] + R[0] + R[2:] for L, R in splits if len(R) > 1]
        replaces = [L + c + R[1:] for L, R in splits if R for c in letters]
        inserts = [L + c + R for L, R in splits for c in letters]
        return set(deletes + transposes + replaces + inserts)

    def get_edits2(word):
        """All edits that are two edits away from `word`."""
        return (e2 for e1 in get_edits1(word) for e2 in get_edits1(e1))

    return get_correction(word_to_check)
