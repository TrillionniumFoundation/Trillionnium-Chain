"""Independent scalar rule for the frozen complete evaluator set, not ML truth."""
PROFILE = "closed-round-all-eligible-min-v1"

def complete_score(evaluators, author, votes, maximum):
    eligible = set(evaluators) - {author}
    if not 2 <= len(eligible) <= 3:
        raise ValueError("EVALUATOR_ROSTER")
    if not set(votes) <= eligible:
        raise ValueError("AUTHORITY")
    scores = [vote['score'] for vote in votes.values()]
    if type(maximum) is not int or any(type(v) is not int or not 0 <= v <= maximum for v in scores):
        raise ValueError("EVIDENCE")
    if set(votes) != eligible:
        return None
    return min(scores)
