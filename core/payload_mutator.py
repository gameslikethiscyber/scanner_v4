import urllib.parse
import random
from typing import List


class PayloadMutator:
    @staticmethod
    def url_encode(payload: str) -> str:
        return urllib.parse.quote(payload, safe='')

    @staticmethod
    def double_url_encode(payload: str) -> str:
        return urllib.parse.quote(urllib.parse.quote(payload, safe=''), safe='')

    @staticmethod
    def hex_encode(payload: str) -> str:
        return ''.join(f'%{ord(c):02x}' for c in payload)

    @staticmethod
    def double_hex_encode(payload: str) -> str:
        first = ''.join(f'%{ord(c):02x}' for c in payload)
        return ''.join(f'%{ord(c):02x}' for c in first)

    @staticmethod
    def case_variation(payload: str) -> str:
        result = []
        for c in payload:
            if c.isalpha():
                result.append(c.upper() if random.choice([True, False]) else c.lower())
            else:
                result.append(c)
        return ''.join(result)

    @staticmethod
    def sql_comment_injection(payload: str) -> str:
        for keyword in [' OR ', ' AND ', 'WHERE ', 'UNION ', 'SELECT ', 'FROM ', 'SLEEP', 'pg_sleep']:
            if keyword in payload.upper():
                idx = payload.upper().index(keyword)
                original = payload[idx:idx + len(keyword)]
                mutated = original.replace(' ', '/**/')
                payload = payload[:idx] + mutated + payload[idx + len(keyword):]
        return payload

    @staticmethod
    def whitespace_insertion(payload: str) -> str:
        for keyword in ['OR', 'AND', 'UNION', 'SELECT', 'WHERE', 'FROM']:
            payload = payload.replace(keyword, f'{keyword[0]} {keyword[1:]}')
        return payload

    @staticmethod
    def html_entity_encode(payload: str) -> str:
        mapping = {
            '<': '&lt;',
            '>': '&gt;',
            '"': '&quot;',
            "'": '&#x27;',
            '&': '&amp;',
        }
        result = []
        for c in payload:
            if c in mapping:
                result.append(mapping[c])
            elif ord(c) > 127:
                result.append(f'&#{ord(c)};')
            else:
                result.append(c)
        payload_str = ''.join(result)

        for tag in ['script', 'img', 'svg', 'iframe', 'body', 'input']:
            if tag in payload_str.lower():
                idx = payload_str.lower().index(tag)
                for c in tag:
                    payload_str = payload_str[:idx] + (c.upper() if random.choice([True, False]) else c.lower()) + payload_str[idx + 1:]
                    idx += 1
        return payload_str

    @staticmethod
    def unicode_escape(payload: str) -> str:
        return ''.join(f'\\u{ord(c):04x}' for c in payload)

    @staticmethod
    def mixed_mutation(payload: str, technique: str = 'auto') -> str:
        mutations = {
            'url': PayloadMutator.url_encode,
            'double_url': PayloadMutator.double_url_encode,
            'hex': PayloadMutator.hex_encode,
            'double_hex': PayloadMutator.double_hex_encode,
            'case': PayloadMutator.case_variation,
            'sql_comment': PayloadMutator.sql_comment_injection,
            'whitespace': PayloadMutator.whitespace_insertion,
            'html_entity': PayloadMutator.html_entity_encode,
            'unicode': PayloadMutator.unicode_escape,
        }

        if technique == 'auto':
            technique = random.choice(list(mutations.keys()))

        mutator = mutations.get(technique)
        if mutator:
            return mutator(payload)
        return payload

    @staticmethod
    def generate_mutations(payload: str) -> List[str]:
        mutations = []
        techniques = ['url', 'double_url', 'hex', 'double_hex', 'case', 'sql_comment', 'whitespace', 'html_entity', 'unicode']
        for technique in techniques:
            try:
                mutated = PayloadMutator.mixed_mutation(payload, technique)
                if mutated != payload:
                    mutations.append(mutated)
            except Exception:
                continue

        combined = payload
        for technique in ['url', 'case']:
            try:
                combined = PayloadMutator.mixed_mutation(combined, technique)
            except Exception:
                pass
        if combined != payload:
            mutations.append(combined)

        return mutations[:10]
