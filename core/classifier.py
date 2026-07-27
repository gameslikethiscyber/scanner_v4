"""
Dynamic Confidence & Classification Engine
Calculates confidence based on evidence strength and quantity
"""

class Classifier:
    def __init__(self):
        self.confidence_weights = {
            'error_based': 50,
            'boolean_based': 30,
            'time_based': 20,
            'multiple_evidence': 10,
            'database_fingerprint': 10
        }
    
    def classify_finding(self, finding_data):
        """
        Classify and assign confidence to a finding
        
        Args:
            finding_data: Dict containing evidence and test results
        
        Returns:
            Dict with classification and confidence
        """
        confidence = 0
        evidence_count = 0
        
        # Check evidence types
        evidence = finding_data.get('evidence', [])
        
        # Weight by evidence type
        for ev in evidence:
            ev_type = ev.get('type')
            if ev_type == 'error-based':
                confidence += self.confidence_weights['error_based']
                evidence_count += 1
            elif ev_type == 'boolean-based':
                confidence += self.confidence_weights['boolean_based']
                evidence_count += 1
            elif ev_type == 'time-based':
                confidence += self.confidence_weights['time_based']
                evidence_count += 1
        
        # Bonus for multiple evidence types
        if evidence_count >= 3:
            confidence += self.confidence_weights['multiple_evidence']
        
        # Bonus for database fingerprint
        if finding_data.get('database'):
            confidence += self.confidence_weights['database_fingerprint']
        
        # Confidence boost based on evidence quality
        quality_score = self.assess_evidence_quality(finding_data.get('evidence', []))
        confidence = min(100, confidence + quality_score)
        
        # Determine severity based on confidence
        if confidence >= 80:
            severity = 'Critical'
        elif confidence >= 60:
            severity = 'High'
        elif confidence >= 40:
            severity = 'Medium'
        elif confidence >= 20:
            severity = 'Low'
        else:
            severity = 'Info'
        
        return {
            'confidence': confidence,
            'severity': severity,
            'category': self.determine_category(confidence, finding_data),
            'evidence_count': evidence_count
        }
    
    def assess_evidence_quality(self, evidence):
        """Assess the quality of collected evidence"""
        if not evidence:
            return 0
        
        quality_score = 0
        for ev in evidence:
            # More detailed evidence is more reliable
            if 'database' in ev:
                quality_score += 5
            if 'pattern' in ev and ev['pattern']:
                quality_score += 5
            if 'payload' in ev and ev['payload']:
                quality_score += 3
            if 'difference' in ev and ev['difference'] > 0.5:
                quality_score += 5
            if 'elapsed_time' in ev and ev['elapsed_time'] > 0:
                quality_score += 5
        
        return min(20, quality_score)  # Max 20 bonus points
    
    def determine_category(self, confidence, finding_data):
        """Determine finding category"""
        if confidence >= 70:
            return 'Confirmed Vulnerability'
        elif confidence >= 40:
            return 'Possible Vulnerability'
        elif confidence >= 20:
            return 'Misconfiguration'
        else:
            return 'Best Practice'