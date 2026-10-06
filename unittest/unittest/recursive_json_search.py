"""Recursive JSON search with field-level role permissions."""

from policy import POLICY


def _can_read_container(value, role):
    """Prevent a matched container from disclosing unauthorized descendants."""
    if isinstance(value, dict):
        return all(
            role in POLICY.get(key, ()) and _can_read_container(child, role)
            for key, child in value.items()
        )
    if isinstance(value, list):
        return all(_can_read_container(child, role) for child in value)
    return True


def json_search(key, input_object, role=None):
    """Return permitted {key: value} matches, denying unknown keys and roles.

    A matching container is omitted if any descendant field is unauthorized.
    Its children are still searched for independently authorized matches.
    The caller must obtain role from a trusted authentication context.
    """
    if role not in POLICY.get(key, ()):
        return []

    results = []
    if isinstance(input_object, dict):
        for current_key, value in input_object.items():
            if current_key == key and _can_read_container(value, role):
                results.append({key: value})
            results.extend(json_search(key, value, role=role))
    elif isinstance(input_object, list):
        for item in input_object:
            results.extend(json_search(key, item, role=role))
    return results
