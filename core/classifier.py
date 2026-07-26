class Classifier:
    def __init__(self, findings):
        self.findings = findings

    def classify(self):
        result = {'confirmed': [], 'possible': [], 'misconfig': [], 'bestpractice': []}

        for f in self.findings:
            t = f.get('type', '')
            if t == 'confirmed':
                result['confirmed'].append(f)
            elif t == 'possible':
                result['possible'].append(f)
            elif t == 'misconfig':
                result['misconfig'].append(f)
            else:
                result['bestpractice'].append(f)

        # Sort by confidence desc
        for key in result:
            result[key].sort(key=lambda x: x['confidence'], reverse=True)

        return result
