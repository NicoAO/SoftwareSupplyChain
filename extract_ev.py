import re
import pandas as pd


def extract_company(desc):
    if pd.isna(desc):
        return None
    s = desc.strip()
    m = re.search(r'Vendor[:\s]+([A-Z][\w&.\- ]{1,60}?)(?:,|;|\.|$)', s)
    if m:
        return m.group(1).strip()
    m = re.search(r'Product[:\s]+([A-Z][\w&.\- ]{1,60}?)(?:,|;|\.|$)', s)
    if m:
        return m.group(1).strip()
    m = re.search(r'by\s+([A-Z][\w&.\- ]{1,60}?)(?:,|;|\.|$)', s)
    if m:
        return m.group(1).strip()
    m = re.match(r'^(?:An?\s+|The\s+)?([A-Z][a-zA-Z0-9&\.\-]+(?:\s+[A-Z][a-zA-Z0-9&\.\-]+){0,3})', s)
    if m:
        return m.group(1).strip()
    return None


vuln_keywords = {
    'Remote Code Execution': ['remote code execution','rce','remote command execution','execute arbitrary code'],
    'SQL Injection': ['sql injection','sqli'],
    'Cross-Site Scripting': ['cross-site scripting','xss','cross site scripting'],
    'Buffer Overflow': ['buffer overflow','stack overflow'],
    'Privilege Escalation': ['privilege escalation'],
    'Authentication Bypass': ['authentication bypass','bypass authentication'],
    'Information Disclosure': ['information disclosure','sensitive information','information leak','data leak'],
    'Denial of Service': ['denial of service','dos','denial-of-service'],
    'Directory Traversal': ['directory traversal','path traversal'],
    'Command Injection': ['command injection']
}


def extract_vuln(desc):
    if pd.isna(desc):
        return None
    s = desc.lower()
    for label, kws in vuln_keywords.items():
        for kw in kws:
            if kw in s:
                return label
    m = re.search(r'vulnerab(?:ility|le) (?:that )?(?:allows|allows for|allows an attacker to|permits|permit) (.+?)[\.,]', s)
    if m:
        return m.group(1)[:80]
    return None


if __name__ == '__main__':
    ev = pd.read_csv('known_exploited_vulnerabilities.csv')
    ev['company'] = ev['shortDescription'].apply(extract_company)
    ev['vuln_type'] = ev['shortDescription'].apply(extract_vuln)
    print(ev[['shortDescription','company','vuln_type']].head(20).to_string(index=False))
    ev[['shortDescription','company','vuln_type']].to_csv('ev_extracted.csv', index=False)
    print('Saved ev_extracted.csv')