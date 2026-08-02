from urllib.parse import urlparse, parse_qs, urlencode, urlunparse


def inject_payload_to_url(url: str, param: str, payload: str) -> str:
    parsed = urlparse(url)
    query_dict = parse_qs(parsed.query, keep_blank_values=True)
    query_dict[param] = [payload]
    new_query = urlencode(query_dict, doseq=True)
    return urlunparse((parsed.scheme, parsed.netloc, parsed.path, parsed.params, new_query, parsed.fragment))
