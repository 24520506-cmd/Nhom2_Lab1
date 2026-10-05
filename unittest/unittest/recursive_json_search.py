from test_data import *
from policy import POLICY


def json_search(key, input_object, role=None):
    # Key có policy nhưng role không được phép: từ chối ngay
    if key in POLICY and role not in POLICY[key]:
        return []

    ret_val = []

    if isinstance(input_object, dict):
        for k, v in input_object.items():
            if k == key:
                ret_val.append({k: v})

            if isinstance(v, (dict, list)):
                ret_val.extend(json_search(key, v, role))

    elif isinstance(input_object, list):
        for item in input_object:
            if isinstance(item, (dict, list)):
                ret_val.extend(json_search(key, item, role))

    return ret_val


if __name__ == "__main__":
    print(json_search("issueSummary", data, role="viewer"))